//! User management endpoints

use axum::{Router, Json, extract::{Path, Query, State}};
use axum::routing::{get, post, put, delete};
use std::sync::Arc;
use uuid::Uuid;
use crate::{ApiState, models::*};

pub fn router() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/:id", get(get_user).put(update_user).delete(delete_user))
}

#[derive(serde::Deserialize)]
pub struct ListParams {
    page: Option<u32>,
    per_page: Option<u32>,
    role: Option<String>,
}

/// List all users
#[utoipa::path(
    get,
    path = "/api/v1/users",
    params(
        ("page" = Option<u32>, Query, description = "Page number"),
        ("per_page" = Option<u32>, Query, description = "Items per page"),
        ("role" = Option<String>, Query, description = "Filter by role")
    ),
    responses(
        (status = 200, description = "List of users", body = PaginatedResponse<User>)
    ),
    tag = "users",
    security(("api_key" = []))
)]
pub async fn list_users(
    Query(params): Query<ListParams>,
) -> Json<ApiResponse<PaginatedResponse<User>>> {
    let page = params.page.unwrap_or(1);
    let per_page = params.per_page.unwrap_or(20);
    
    // Mock data
    let users = vec![
        User {
            id: Uuid::new_v4(),
            email: "admin@example.com".into(),
            name: "Admin User".into(),
            role: UserRole::Admin,
            mfa_enabled: true,
            status: "active".into(),
            created_at: chrono::Utc::now(),
            last_login: Some(chrono::Utc::now()),
        },
    ];

    Json(ApiResponse::success(PaginatedResponse {
        items: users,
        total: 1,
        page,
        per_page,
        total_pages: 1,
    }))
}

/// Get user by ID
#[utoipa::path(
    get,
    path = "/api/v1/users/{id}",
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User details", body = ApiResponse<User>),
        (status = 404, description = "User not found")
    ),
    tag = "users"
)]
pub async fn get_user(Path(id): Path<Uuid>) -> Json<ApiResponse<User>> {
    Json(ApiResponse::success(User {
        id,
        email: "user@example.com".into(),
        name: "Example User".into(),
        role: UserRole::Editor,
        mfa_enabled: false,
        status: "active".into(),
        created_at: chrono::Utc::now(),
        last_login: None,
    }))
}

/// Create a new user
#[utoipa::path(
    post,
    path = "/api/v1/users",
    request_body = UserCreate,
    responses(
        (status = 201, description = "User created", body = ApiResponse<User>),
        (status = 400, description = "Invalid input")
    ),
    tag = "users"
)]
pub async fn create_user(Json(input): Json<UserCreate>) -> Json<ApiResponse<User>> {
    Json(ApiResponse::success(User {
        id: Uuid::new_v4(),
        email: input.email,
        name: input.name,
        role: input.role,
        mfa_enabled: false,
        status: "pending".into(),
        created_at: chrono::Utc::now(),
        last_login: None,
    }))
}

pub async fn update_user(
    Path(id): Path<Uuid>,
    Json(input): Json<UserCreate>,
) -> Json<ApiResponse<User>> {
    Json(ApiResponse::success(User {
        id,
        email: input.email,
        name: input.name,
        role: input.role,
        mfa_enabled: false,
        status: "active".into(),
        created_at: chrono::Utc::now(),
        last_login: None,
    }))
}

pub async fn delete_user(Path(id): Path<Uuid>) -> Json<ApiResponse<()>> {
    Json(ApiResponse::success(()))
}
