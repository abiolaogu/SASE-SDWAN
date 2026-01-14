//! Analytics endpoints

use axum::{Router, Json, extract::Query};
use axum::routing::get;
use std::sync::Arc;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/traffic", get(get_traffic_stats))
        .route("/threats", get(get_threat_stats))
}

#[derive(serde::Deserialize)]
pub struct TimeRangeParams {
    period: Option<String>,  // 1h, 24h, 7d, 30d
}

/// Get traffic statistics
#[utoipa::path(
    get,
    path = "/api/v1/analytics/traffic",
    params(("period" = Option<String>, Query, description = "Time period")),
    responses((status = 200, body = ApiResponse<TrafficStats>)),
    tag = "analytics"
)]
pub async fn get_traffic_stats(
    Query(params): Query<TimeRangeParams>,
) -> Json<ApiResponse<TrafficStats>> {
    Json(ApiResponse::success(TrafficStats {
        period: params.period.unwrap_or("24h".into()),
        total_bytes: 150_000_000_000,
        total_requests: 5_000_000,
        blocked_requests: 15_000,
        top_applications: vec![
            AppUsage { name: "Microsoft 365".into(), bytes: 50_000_000_000, percentage: 33.3 },
            AppUsage { name: "Google Workspace".into(), bytes: 30_000_000_000, percentage: 20.0 },
            AppUsage { name: "Slack".into(), bytes: 10_000_000_000, percentage: 6.7 },
        ],
    }))
}

/// Get threat statistics
#[utoipa::path(
    get,
    path = "/api/v1/analytics/threats",
    params(("period" = Option<String>, Query)),
    responses((status = 200, body = ApiResponse<ThreatStats>)),
    tag = "analytics"
)]
pub async fn get_threat_stats(
    Query(params): Query<TimeRangeParams>,
) -> Json<ApiResponse<ThreatStats>> {
    Json(ApiResponse::success(ThreatStats {
        period: params.period.unwrap_or("24h".into()),
        total_threats: 1250,
        by_category: vec![
            ThreatCategory { name: "Malware".into(), count: 450 },
            ThreatCategory { name: "Phishing".into(), count: 380 },
            ThreatCategory { name: "C2".into(), count: 120 },
        ],
        top_blocked_domains: vec![
            "malware.example.com".into(),
            "phishing.bad.com".into(),
        ],
    }))
}
