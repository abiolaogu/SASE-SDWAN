//! Tunnel management endpoints

use axum::{Router, Json, extract::Path};
use axum::routing::get;
use std::sync::Arc;
use uuid::Uuid;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_tunnels))
        .route("/:id/stats", get(get_tunnel_stats))
}

/// List all tunnels
#[utoipa::path(
    get,
    path = "/api/v1/tunnels",
    responses((status = 200, body = PaginatedResponse<Tunnel>)),
    tag = "tunnels"
)]
pub async fn list_tunnels() -> Json<ApiResponse<PaginatedResponse<Tunnel>>> {
    Json(ApiResponse::success(PaginatedResponse {
        items: vec![
            Tunnel {
                id: Uuid::new_v4(),
                name: "HQ-to-PoP1".into(),
                tunnel_type: "wireguard".into(),
                status: "up".into(),
                local_ip: "10.0.0.1".into(),
                remote_ip: "45.67.89.10".into(),
                created_at: chrono::Utc::now(),
            },
        ],
        total: 1, page: 1, per_page: 20, total_pages: 1,
    }))
}

/// Get tunnel statistics
#[utoipa::path(
    get,
    path = "/api/v1/tunnels/{id}/stats",
    params(("id" = Uuid, Path)),
    responses((status = 200, body = ApiResponse<TunnelStats>)),
    tag = "tunnels"
)]
pub async fn get_tunnel_stats(Path(id): Path<Uuid>) -> Json<ApiResponse<TunnelStats>> {
    Json(ApiResponse::success(TunnelStats {
        tunnel_id: id,
        latency_ms: 15,
        jitter_ms: 2,
        packet_loss_percent: 0.01,
        rx_bytes: 1_500_000_000,
        tx_bytes: 500_000_000,
        uptime_seconds: 86400,
    }))
}
