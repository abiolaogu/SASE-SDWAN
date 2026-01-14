//! Alert management endpoints

use axum::{Router, Json, extract::{Path, Query}};
use axum::routing::{get, post, put};
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_alerts))
        .route("/:id", get(get_alert).put(update_alert))
        .route("/:id/acknowledge", post(acknowledge_alert))
        .route("/:id/resolve", post(resolve_alert))
}

/// Alert
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Alert {
    pub id: Uuid,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub source_ip: Option<String>,
    pub user_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct AlertListParams {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// List alerts
pub async fn list_alerts(
    Path(tenant_id): Path<Uuid>,
    Query(params): Query<AlertListParams>,
) -> Json<ApiResponse<PaginatedResponse<Alert>>> {
    Json(ApiResponse::success(PaginatedResponse {
        items: vec![
            Alert {
                id: Uuid::new_v4(),
                severity: "high".into(),
                category: "threat".into(),
                title: "Malware C2 Communication Detected".into(),
                description: "Device 10.0.1.50 communicating with known C2 server".into(),
                status: "open".into(),
                source_ip: Some("10.0.1.50".into()),
                user_id: Some("user_123".into()),
                created_at: chrono::Utc::now(),
                acknowledged_at: None,
                resolved_at: None,
            },
            Alert {
                id: Uuid::new_v4(),
                severity: "medium".into(),
                category: "policy".into(),
                title: "Policy Violation: Unauthorized SaaS Access".into(),
                description: "User attempted to access blocked application".into(),
                status: "acknowledged".into(),
                source_ip: Some("10.0.1.100".into()),
                user_id: Some("user_456".into()),
                created_at: chrono::Utc::now() - chrono::Duration::hours(2),
                acknowledged_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                resolved_at: None,
            },
        ],
        total: 2,
        page: params.page.unwrap_or(1),
        per_page: params.per_page.unwrap_or(20),
        total_pages: 1,
    }))
}

/// Get alert
pub async fn get_alert(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
) -> Json<ApiResponse<Alert>> {
    Json(ApiResponse::success(Alert {
        id,
        severity: "high".into(),
        category: "threat".into(),
        title: "Suspicious DNS Query".into(),
        description: "High entropy domain detected".into(),
        status: "open".into(),
        source_ip: Some("10.0.1.50".into()),
        user_id: None,
        created_at: chrono::Utc::now(),
        acknowledged_at: None,
        resolved_at: None,
    }))
}

/// Update alert
#[derive(Debug, Deserialize)]
pub struct AlertUpdate {
    pub status: Option<String>,
    pub notes: Option<String>,
}

pub async fn update_alert(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
    Json(input): Json<AlertUpdate>,
) -> Json<ApiResponse<Alert>> {
    Json(ApiResponse::success(Alert {
        id,
        severity: "high".into(),
        category: "threat".into(),
        title: "Alert Updated".into(),
        description: "".into(),
        status: input.status.unwrap_or("open".into()),
        source_ip: None,
        user_id: None,
        created_at: chrono::Utc::now(),
        acknowledged_at: None,
        resolved_at: None,
    }))
}

/// Acknowledge alert
pub async fn acknowledge_alert(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
) -> Json<ApiResponse<Alert>> {
    Json(ApiResponse::success(Alert {
        id,
        severity: "high".into(),
        category: "threat".into(),
        title: "Alert".into(),
        description: "".into(),
        status: "acknowledged".into(),
        source_ip: None,
        user_id: None,
        created_at: chrono::Utc::now(),
        acknowledged_at: Some(chrono::Utc::now()),
        resolved_at: None,
    }))
}

/// Resolve alert
pub async fn resolve_alert(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
) -> Json<ApiResponse<Alert>> {
    Json(ApiResponse::success(Alert {
        id,
        severity: "high".into(),
        category: "threat".into(),
        title: "Alert".into(),
        description: "".into(),
        status: "resolved".into(),
        source_ip: None,
        user_id: None,
        created_at: chrono::Utc::now(),
        acknowledged_at: Some(chrono::Utc::now()),
        resolved_at: Some(chrono::Utc::now()),
    }))
}
