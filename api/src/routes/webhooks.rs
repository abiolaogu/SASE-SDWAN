//! Webhook management endpoints

use axum::{Router, Json, extract::Path};
use axum::routing::{get, post, delete};
use std::sync::Arc;
use uuid::Uuid;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_webhooks).post(create_webhook))
        .route("/:id", delete(delete_webhook))
        .route("/:id/test", post(test_webhook))
}

pub async fn list_webhooks() -> Json<ApiResponse<Vec<Webhook>>> {
    Json(ApiResponse::success(vec![
        Webhook {
            id: Uuid::new_v4(),
            url: "https://example.com/webhook".into(),
            events: vec!["threat.detected".into(), "policy.changed".into()],
            secret: "whsec_****".into(),
            enabled: true,
            created_at: chrono::Utc::now(),
        },
    ]))
}

pub async fn create_webhook(Json(input): Json<WebhookCreate>) -> Json<ApiResponse<Webhook>> {
    let secret = format!("whsec_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    Json(ApiResponse::success(Webhook {
        id: Uuid::new_v4(),
        url: input.url,
        events: input.events,
        secret,
        enabled: true,
        created_at: chrono::Utc::now(),
    }))
}

pub async fn delete_webhook(Path(_id): Path<Uuid>) -> Json<ApiResponse<()>> {
    Json(ApiResponse::success(()))
}

pub async fn test_webhook(Path(_id): Path<Uuid>) -> Json<ApiResponse<WebhookTestResult>> {
    Json(ApiResponse::success(WebhookTestResult {
        success: true,
        status_code: 200,
        response_time_ms: 150,
    }))
}

#[derive(serde::Serialize)]
pub struct WebhookTestResult {
    success: bool,
    status_code: u16,
    response_time_ms: u32,
}
