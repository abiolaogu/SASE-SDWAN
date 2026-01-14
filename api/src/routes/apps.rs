//! Application management endpoints

use axum::{Router, Json, extract::Path};
use axum::routing::{get, post, put};
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_apps).post(create_app))
        .route("/:id", get(get_app).put(update_app))
        .route("/:id/rules", get(get_app_rules).post(add_app_rule))
}

/// Application
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub risk_score: u8,
    pub enabled: bool,
    pub action: String,
    pub bandwidth_limit_mbps: Option<u32>,
}

/// Application create
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AppCreate {
    pub name: String,
    pub category: String,
    pub action: String,
}

/// List apps
pub async fn list_apps(
    Path(tenant_id): Path<Uuid>,
) -> Json<ApiResponse<PaginatedResponse<Application>>> {
    Json(ApiResponse::success(PaginatedResponse {
        items: vec![
            Application {
                id: Uuid::new_v4(),
                name: "Microsoft 365".into(),
                category: "productivity".into(),
                risk_score: 1,
                enabled: true,
                action: "allow".into(),
                bandwidth_limit_mbps: None,
            },
            Application {
                id: Uuid::new_v4(),
                name: "Dropbox".into(),
                category: "file_sharing".into(),
                risk_score: 3,
                enabled: true,
                action: "allow".into(),
                bandwidth_limit_mbps: Some(100),
            },
        ],
        total: 2,
        page: 1,
        per_page: 20,
        total_pages: 1,
    }))
}

/// Get app
pub async fn get_app(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
) -> Json<ApiResponse<Application>> {
    Json(ApiResponse::success(Application {
        id,
        name: "Zoom".into(),
        category: "video_conferencing".into(),
        risk_score: 2,
        enabled: true,
        action: "allow".into(),
        bandwidth_limit_mbps: None,
    }))
}

/// Create app rule
pub async fn create_app(
    Path(tenant_id): Path<Uuid>,
    Json(input): Json<AppCreate>,
) -> Json<ApiResponse<Application>> {
    Json(ApiResponse::success(Application {
        id: Uuid::new_v4(),
        name: input.name,
        category: input.category,
        risk_score: 5,
        enabled: true,
        action: input.action,
        bandwidth_limit_mbps: None,
    }))
}

/// Update app
pub async fn update_app(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
    Json(input): Json<AppCreate>,
) -> Json<ApiResponse<Application>> {
    Json(ApiResponse::success(Application {
        id,
        name: input.name,
        category: input.category,
        risk_score: 5,
        enabled: true,
        action: input.action,
        bandwidth_limit_mbps: None,
    }))
}

/// App rule
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AppRule {
    pub id: Uuid,
    pub app_id: Uuid,
    pub rule_type: String,
    pub value: String,
}

/// Get app rules
pub async fn get_app_rules(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
) -> Json<ApiResponse<Vec<AppRule>>> {
    Json(ApiResponse::success(vec![
        AppRule {
            id: Uuid::new_v4(),
            app_id: id,
            rule_type: "domain".into(),
            value: "*.microsoft.com".into(),
        },
    ]))
}

/// Add app rule
pub async fn add_app_rule(
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
    Json(input): Json<AppRule>,
) -> Json<ApiResponse<AppRule>> {
    Json(ApiResponse::success(AppRule {
        id: Uuid::new_v4(),
        app_id: id,
        rule_type: input.rule_type,
        value: input.value,
    }))
}
