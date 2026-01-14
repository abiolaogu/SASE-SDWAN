//! Local API Server

use crate::{EdgeError, EdgeConfig};
use axum::{routing::get, Json, Router};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::Serialize;

/// Start local API server
pub async fn start_server(config: Arc<RwLock<EdgeConfig>>) -> Result<(), EdgeError> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/interfaces", get(interfaces))
        .route("/tunnels", get(tunnels))
        .route("/stats", get(stats));

    let addr = "0.0.0.0:8080";
    tracing::info!("Edge API listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await
        .map_err(|e| EdgeError::Network(e.to_string()))?;
    
    axum::serve(listener, app).await
        .map_err(|e| EdgeError::Network(e.to_string()))
}

async fn health() -> &'static str {
    "OK"
}

async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        state: "running".into(),
        uptime_secs: 3600,
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

async fn interfaces() -> Json<Vec<InterfaceInfo>> {
    Json(vec![
        InterfaceInfo { name: "eth0".into(), role: "wan".into(), status: "up".into(), ip: "192.168.1.100".into() },
        InterfaceInfo { name: "eth1".into(), role: "lan".into(), status: "up".into(), ip: "10.0.0.1".into() },
    ])
}

async fn tunnels() -> Json<Vec<TunnelInfo>> {
    Json(vec![
        TunnelInfo { pop_id: "pop-us-east".into(), status: "connected".into(), latency_ms: 25 },
    ])
}

async fn stats() -> Json<StatsResponse> {
    Json(StatsResponse {
        packets_processed: 1_000_000,
        bytes_sent: 500_000_000,
        bytes_received: 1_200_000_000,
        threats_blocked: 42,
    })
}

#[derive(Serialize)]
struct StatusResponse {
    state: String,
    uptime_secs: u64,
    version: String,
}

#[derive(Serialize)]
struct InterfaceInfo {
    name: String,
    role: String,
    status: String,
    ip: String,
}

#[derive(Serialize)]
struct TunnelInfo {
    pop_id: String,
    status: String,
    latency_ms: u32,
}

#[derive(Serialize)]
struct StatsResponse {
    packets_processed: u64,
    bytes_sent: u64,
    bytes_received: u64,
    threats_blocked: u64,
}
