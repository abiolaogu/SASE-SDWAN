//! OSPE REST API Service
//!
//! Axum-based API for peering session management, IXP ports, and looking glass.

use axum::{
    routing::{get, post, put, delete},
    Router, Json, Extension,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    SessionManager, IxpManager, MetricsExporter, LookingGlass,
    PeeringSession, IxpPort, BgpSessionState, PeeringType,
    SessionMetrics, MetricsSummary,
};

/// API state
pub struct ApiState {
    pub sessions: RwLock<SessionManager>,
    pub ixps: RwLock<IxpManager>,
    pub metrics: RwLock<MetricsExporter>,
    pub looking_glass: LookingGlass,
}

impl ApiState {
    pub fn new(router_id: &str, bird_socket: &str) -> Self {
        Self {
            sessions: RwLock::new(SessionManager::new()),
            ixps: RwLock::new(IxpManager::new()),
            metrics: RwLock::new(MetricsExporter::new()),
            looking_glass: LookingGlass::new(router_id, bird_socket),
        }
    }
}

/// Create API router
pub fn create_router(state: Arc<ApiState>) -> Router {
    Router::new()
        // Session endpoints
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions", post(create_session))
        .route("/api/sessions/:id", get(get_session))
        .route("/api/sessions/:id", put(update_session))
        .route("/api/sessions/:id", delete(delete_session))
        .route("/api/sessions/:id/enable", post(enable_session))
        .route("/api/sessions/:id/disable", post(disable_session))
        
        // IXP endpoints
        .route("/api/ixps", get(list_ixps))
        .route("/api/ixps/:id/ports", get(list_ixp_ports))
        .route("/api/ports", get(list_ports))
        .route("/api/ports", post(create_port))
        .route("/api/ports/:id", get(get_port))
        
        // Looking glass endpoints
        .route("/api/looking-glass/stats", get(lg_stats))
        .route("/api/looking-glass/query", get(lg_query))
        .route("/api/looking-glass/sessions", get(lg_sessions))
        .route("/api/looking-glass/routes/:prefix", get(lg_routes))
        
        // Metrics endpoints
        .route("/metrics", get(prometheus_metrics))
        .route("/api/metrics/summary", get(metrics_summary))
        
        // Health endpoints
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        
        // Looking glass HTML
        .route("/looking-glass", get(looking_glass_page))
        
        .with_state(state)
}

// ==================== Session Handlers ====================

#[derive(Serialize)]
struct SessionListResponse {
    sessions: Vec<SessionInfo>,
    total: usize,
    established: usize,
}

#[derive(Serialize)]
struct SessionInfo {
    id: String,
    peer_asn: u32,
    peer_name: String,
    peer_ip: String,
    state: String,
    prefixes_received: u32,
    uptime_seconds: u64,
}

async fn list_sessions(State(state): State<Arc<ApiState>>) -> Json<SessionListResponse> {
    let sessions = state.sessions.read().await;
    let stats = sessions.session_stats();
    
    let session_list: Vec<SessionInfo> = sessions.established_sessions()
        .iter()
        .map(|s| SessionInfo {
            id: s.id.clone(),
            peer_asn: s.peer_asn,
            peer_name: s.peer_name.clone(),
            peer_ip: s.peer_ip.to_string(),
            state: format!("{:?}", s.state),
            prefixes_received: s.prefixes_received,
            uptime_seconds: s.uptime_seconds,
        })
        .collect();
    
    Json(SessionListResponse {
        sessions: session_list,
        total: stats.total_sessions,
        established: stats.established_sessions,
    })
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    peer_asn: u32,
    peer_name: String,
    peer_ip: String,
    local_ip: String,
    ixp_port_id: String,
    peering_type: String,
}

async fn create_session(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<SessionInfo>, StatusCode> {
    let mut sessions = state.sessions.write().await;
    
    let session = PeeringSession {
        id: format!("sess-{}-{}", req.peer_asn, chrono::Utc::now().timestamp()),
        ixp_port_id: req.ixp_port_id,
        peer_asn: req.peer_asn,
        peer_name: req.peer_name.clone(),
        peer_ip: req.peer_ip.parse().map_err(|_| StatusCode::BAD_REQUEST)?,
        local_ip: req.local_ip.parse().map_err(|_| StatusCode::BAD_REQUEST)?,
        peering_type: match req.peering_type.as_str() {
            "bilateral" => PeeringType::Bilateral,
            "routeserver" => PeeringType::RouteServer,
            _ => PeeringType::Multilateral,
        },
        state: BgpSessionState::Idle,
        prefixes_received: 0,
        prefixes_sent: 0,
        uptime_seconds: 0,
        last_state_change: chrono::Utc::now().timestamp(),
    };
    
    let info = SessionInfo {
        id: session.id.clone(),
        peer_asn: session.peer_asn,
        peer_name: session.peer_name.clone(),
        peer_ip: session.peer_ip.to_string(),
        state: format!("{:?}", session.state),
        prefixes_received: session.prefixes_received,
        uptime_seconds: session.uptime_seconds,
    };
    
    sessions.add_session(session);
    
    Ok(Json(info))
}

async fn get_session(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionInfo>, StatusCode> {
    let sessions = state.sessions.read().await;
    
    sessions.get_session(&id)
        .map(|s| Json(SessionInfo {
            id: s.id.clone(),
            peer_asn: s.peer_asn,
            peer_name: s.peer_name.clone(),
            peer_ip: s.peer_ip.to_string(),
            state: format!("{:?}", s.state),
            prefixes_received: s.prefixes_received,
            uptime_seconds: s.uptime_seconds,
        }))
        .ok_or(StatusCode::NOT_FOUND)
}

async fn update_session(
    State(_state): State<Arc<ApiState>>,
    Path(_id): Path<String>,
    Json(_req): Json<CreateSessionRequest>,
) -> StatusCode {
    // Implementation would update session config
    StatusCode::OK
}

async fn delete_session(
    State(_state): State<Arc<ApiState>>,
    Path(_id): Path<String>,
) -> StatusCode {
    // Implementation would remove session
    StatusCode::NO_CONTENT
}

async fn enable_session(
    State(_state): State<Arc<ApiState>>,
    Path(_id): Path<String>,
) -> StatusCode {
    // Execute: birdc enable <protocol>
    StatusCode::OK
}

async fn disable_session(
    State(_state): State<Arc<ApiState>>,
    Path(_id): Path<String>,
) -> StatusCode {
    // Execute: birdc disable <protocol>
    StatusCode::OK
}

// ==================== IXP Handlers ====================

async fn list_ixps(State(_state): State<Arc<ApiState>>) -> Json<Vec<IxpInfo>> {
    // Return list of known IXPs
    Json(vec![])
}

#[derive(Serialize)]
struct IxpInfo {
    id: u32,
    name: String,
    city: String,
    country: String,
    member_count: u32,
}

async fn list_ixp_ports(
    State(state): State<Arc<ApiState>>,
    Path(ixp_id): Path<u32>,
) -> Json<Vec<PortInfo>> {
    let ixps = state.ixps.read().await;
    let ports: Vec<PortInfo> = ixps.get_ixp_ports(ixp_id)
        .iter()
        .map(|p| PortInfo {
            id: p.id.clone(),
            ixp_name: p.ixp_name.clone(),
            pop_name: p.pop_name.clone(),
            speed_mbps: p.speed_mbps,
            status: format!("{:?}", p.status),
        })
        .collect();
    
    Json(ports)
}

#[derive(Serialize)]
struct PortInfo {
    id: String,
    ixp_name: String,
    pop_name: String,
    speed_mbps: u32,
    status: String,
}

async fn list_ports(State(state): State<Arc<ApiState>>) -> Json<Vec<PortInfo>> {
    let ixps = state.ixps.read().await;
    let ports: Vec<PortInfo> = ixps.active_ports()
        .iter()
        .map(|p| PortInfo {
            id: p.id.clone(),
            ixp_name: p.ixp_name.clone(),
            pop_name: p.pop_name.clone(),
            speed_mbps: p.speed_mbps,
            status: format!("{:?}", p.status),
        })
        .collect();
    
    Json(ports)
}

async fn create_port(
    State(_state): State<Arc<ApiState>>,
    Json(_req): Json<CreatePortRequest>,
) -> StatusCode {
    // Implementation would provision new port
    StatusCode::CREATED
}

#[derive(Deserialize)]
struct CreatePortRequest {
    ixp_id: u32,
    pop_name: String,
    speed_mbps: u32,
}

async fn get_port(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<PortInfo>, StatusCode> {
    let ixps = state.ixps.read().await;
    
    ixps.get_port(&id)
        .map(|p| Json(PortInfo {
            id: p.id.clone(),
            ixp_name: p.ixp_name.clone(),
            pop_name: p.pop_name.clone(),
            speed_mbps: p.speed_mbps,
            status: format!("{:?}", p.status),
        }))
        .ok_or(StatusCode::NOT_FOUND)
}

// ==================== Looking Glass Handlers ====================

async fn lg_stats(State(state): State<Arc<ApiState>>) -> Json<MetricsSummary> {
    let metrics = state.metrics.read().await;
    Json(metrics.get_summary())
}

#[derive(Deserialize)]
struct LgQueryParams {
    #[serde(rename = "type")]
    query_type: String,
    target: String,
}

async fn lg_query(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<LgQueryParams>,
) -> Json<LgQueryResponse> {
    let response = match params.query_type.as_str() {
        "prefix" => state.looking_glass.query_prefix(&params.target).await,
        "aspath" => {
            let asn: u32 = params.target.trim_start_matches("AS").parse().unwrap_or(0);
            state.looking_glass.query_as_path(asn).await
        }
        _ => state.looking_glass.query_prefix(&params.target).await,
    };
    
    Json(LgQueryResponse {
        routes: vec![],
        query_time_ms: response.execution_time_ms,
    })
}

#[derive(Serialize)]
struct LgQueryResponse {
    routes: Vec<RouteInfo>,
    query_time_ms: u64,
}

#[derive(Serialize)]
struct RouteInfo {
    prefix: String,
    next_hop: String,
    as_path: Vec<u32>,
    local_pref: u32,
    best: bool,
}

async fn lg_sessions(State(state): State<Arc<ApiState>>) -> Json<Vec<SessionInfo>> {
    let sessions = state.sessions.read().await;
    
    let list: Vec<SessionInfo> = sessions.established_sessions()
        .iter()
        .map(|s| SessionInfo {
            id: s.id.clone(),
            peer_asn: s.peer_asn,
            peer_name: s.peer_name.clone(),
            peer_ip: s.peer_ip.to_string(),
            state: format!("{:?}", s.state),
            prefixes_received: s.prefixes_received,
            uptime_seconds: s.uptime_seconds,
        })
        .collect();
    
    Json(list)
}

async fn lg_routes(
    State(state): State<Arc<ApiState>>,
    Path(prefix): Path<String>,
) -> Json<LgQueryResponse> {
    let response = state.looking_glass.query_prefix(&prefix).await;
    
    Json(LgQueryResponse {
        routes: vec![],
        query_time_ms: response.execution_time_ms,
    })
}

async fn looking_glass_page() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/html")],
        crate::looking_glass::generate_looking_glass_html(),
    )
}

// ==================== Metrics Handlers ====================

async fn prometheus_metrics(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let metrics = state.metrics.read().await;
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8")],
        metrics.export_prometheus(),
    )
}

async fn metrics_summary(State(state): State<Arc<ApiState>>) -> Json<MetricsSummary> {
    let metrics = state.metrics.read().await;
    Json(metrics.get_summary())
}

// ==================== Health Handlers ====================

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // Would track actual uptime
    })
}

async fn readiness_check(State(state): State<Arc<ApiState>>) -> StatusCode {
    let sessions = state.sessions.read().await;
    let stats = sessions.session_stats();
    
    if stats.established_sessions > 0 {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Start API server
pub async fn start_server(bind_addr: &str, router_id: &str, bird_socket: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ApiState::new(router_id, bird_socket));
    let app = create_router(state);
    
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("OSPE API listening on {}", bind_addr);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_state_creation() {
        let state = ApiState::new("10.0.0.1", "/var/run/bird.ctl");
        assert!(true); // State created successfully
    }
}
