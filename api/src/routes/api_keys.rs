//! API Key management endpoints

use axum::{Router, Json, extract::Path};
use axum::routing::{get, post, delete};
use std::sync::Arc;
use uuid::Uuid;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_api_keys).post(create_api_key))
        .route("/:id", delete(revoke_api_key))
}

pub async fn list_api_keys() -> Json<ApiResponse<Vec<ApiKey>>> {
    Json(ApiResponse::success(vec![
        ApiKey {
            id: Uuid::new_v4(),
            name: "Production API Key".into(),
            key_prefix: "ops_live_xxxx".into(),
            scopes: vec!["read:all".into(), "write:policies".into()],
            expires_at: None,
            created_at: chrono::Utc::now(),
            last_used: Some(chrono::Utc::now()),
        },
    ]))
}

pub async fn create_api_key(Json(input): Json<ApiKeyCreate>) -> Json<ApiResponse<ApiKeyCreated>> {
    let key = format!("ops_live_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    Json(ApiResponse::success(ApiKeyCreated {
        id: Uuid::new_v4(),
        name: input.name,
        key, // Only shown once!
        scopes: input.scopes,
    }))
}

pub async fn revoke_api_key(Path(_id): Path<Uuid>) -> Json<ApiResponse<()>> {
    Json(ApiResponse::success(()))
}
