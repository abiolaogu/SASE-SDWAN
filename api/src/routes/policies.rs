//! Policy management endpoints

use axum::{Router, Json, extract::Path};
use axum::routing::{get, post, put, delete};
use std::sync::Arc;
use uuid::Uuid;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route("/:id", get(get_policy).put(update_policy).delete(delete_policy))
}

/// List all policies
#[utoipa::path(
    get,
    path = "/api/v1/policies",
    responses(
        (status = 200, description = "List of policies", body = PaginatedResponse<Policy>)
    ),
    tag = "policies"
)]
pub async fn list_policies() -> Json<ApiResponse<PaginatedResponse<Policy>>> {
    Json(ApiResponse::success(PaginatedResponse {
        items: vec![
            Policy {
                id: Uuid::new_v4(),
                name: "Block Malware Sites".into(),
                description: "Block access to known malware domains".into(),
                enabled: true,
                priority: 100,
                conditions: vec![
                    PolicyCondition {
                        field: "threat_category".into(),
                        operator: "equals".into(),
                        value: "malware".into(),
                    }
                ],
                action: PolicyAction::Block,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        ],
        total: 1,
        page: 1,
        per_page: 20,
        total_pages: 1,
    }))
}

/// Get policy by ID
#[utoipa::path(
    get,
    path = "/api/v1/policies/{id}",
    params(("id" = Uuid, Path, description = "Policy ID")),
    responses(
        (status = 200, description = "Policy details", body = ApiResponse<Policy>)
    ),
    tag = "policies"
)]
pub async fn get_policy(Path(id): Path<Uuid>) -> Json<ApiResponse<Policy>> {
    Json(ApiResponse::success(Policy {
        id,
        name: "Default Policy".into(),
        description: "Default access policy".into(),
        enabled: true,
        priority: 1000,
        conditions: vec![],
        action: PolicyAction::Allow,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

/// Create a new policy
#[utoipa::path(
    post,
    path = "/api/v1/policies",
    request_body = PolicyCreate,
    responses(
        (status = 201, description = "Policy created", body = ApiResponse<Policy>)
    ),
    tag = "policies"
)]
pub async fn create_policy(Json(input): Json<PolicyCreate>) -> Json<ApiResponse<Policy>> {
    Json(ApiResponse::success(Policy {
        id: Uuid::new_v4(),
        name: input.name,
        description: input.description,
        enabled: true,
        priority: input.priority,
        conditions: input.conditions,
        action: input.action,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

pub async fn update_policy(
    Path(id): Path<Uuid>,
    Json(input): Json<PolicyCreate>,
) -> Json<ApiResponse<Policy>> {
    Json(ApiResponse::success(Policy {
        id,
        name: input.name,
        description: input.description,
        enabled: true,
        priority: input.priority,
        conditions: input.conditions,
        action: input.action,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

pub async fn delete_policy(Path(id): Path<Uuid>) -> Json<ApiResponse<()>> {
    Json(ApiResponse::success(()))
}
