//! Site management endpoints

use axum::{Router, Json, extract::Path};
use axum::routing::{get, post};
use std::sync::Arc;
use uuid::Uuid;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_sites).post(create_site))
        .route("/:id", get(get_site))
}

/// List all sites
#[utoipa::path(
    get,
    path = "/api/v1/sites",
    responses((status = 200, description = "List of sites", body = PaginatedResponse<Site>)),
    tag = "sites"
)]
pub async fn list_sites() -> Json<ApiResponse<PaginatedResponse<Site>>> {
    Json(ApiResponse::success(PaginatedResponse {
        items: vec![
            Site {
                id: Uuid::new_v4(),
                name: "HQ Office".into(),
                location: "San Francisco, CA".into(),
                status: SiteStatus::Active,
                edge_count: 2,
                user_count: 150,
                created_at: chrono::Utc::now(),
            },
        ],
        total: 1, page: 1, per_page: 20, total_pages: 1,
    }))
}

/// Get site by ID
#[utoipa::path(
    get,
    path = "/api/v1/sites/{id}",
    params(("id" = Uuid, Path)),
    responses((status = 200, body = ApiResponse<Site>)),
    tag = "sites"
)]
pub async fn get_site(Path(id): Path<Uuid>) -> Json<ApiResponse<Site>> {
    Json(ApiResponse::success(Site {
        id,
        name: "Branch Office".into(),
        location: "New York, NY".into(),
        status: SiteStatus::Active,
        edge_count: 1,
        user_count: 50,
        created_at: chrono::Utc::now(),
    }))
}

pub async fn create_site(Json(input): Json<SiteCreate>) -> Json<ApiResponse<Site>> {
    Json(ApiResponse::success(Site {
        id: Uuid::new_v4(),
        name: input.name,
        location: input.location,
        status: SiteStatus::Provisioning,
        edge_count: 0,
        user_count: 0,
        created_at: chrono::Utc::now(),
    }))
}
