//! OpenSASE Developer Platform API
//!
//! Comprehensive REST API for automation and integration.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     DEVELOPER PLATFORM (OSDP)                           │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                         REST API                                 │   │
//! │  │  OpenAPI 3.1 | Rate Limiting | OAuth 2.0 | API Keys             │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │    Rust      │  │   Python     │  │  TypeScript  │  │     Go      │ │
//! │  │     SDK      │  │     SDK      │  │     SDK      │  │    SDK      │ │
//! │  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                       WEBHOOKS                                   │   │
//! │  │   Event Subscriptions | Retry Logic | Signature Verification    │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
//! │  │  Terraform   │  │   Ansible    │  │    CLI       │                  │
//! │  │  Provider    │  │  Collection  │  │              │                  │
//! │  └──────────────┘  └──────────────┘  └──────────────┘                  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod routes;
pub mod middleware;
pub mod models;

use axum::{Router, routing::get};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub use models::*;

/// API state
#[derive(Clone)]
pub struct ApiState {
    /// API version
    pub version: String,
}

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "OpenSASE API",
        version = "1.0.0",
        description = "OpenSASE Developer Platform API - Secure Access Service Edge",
        license(name = "Apache-2.0")
    ),
    paths(
        routes::health::health_check,
        routes::users::list_users,
        routes::users::get_user,
        routes::users::create_user,
        routes::policies::list_policies,
        routes::policies::get_policy,
        routes::policies::create_policy,
        routes::sites::list_sites,
        routes::sites::get_site,
        routes::tunnels::list_tunnels,
        routes::tunnels::get_tunnel_stats,
        routes::analytics::get_traffic_stats,
        routes::analytics::get_threat_stats,
    ),
    components(
        schemas(
            ApiResponse, ErrorResponse, PaginatedResponse,
            User, UserCreate, UserRole,
            Policy, PolicyCreate, PolicyAction,
            Site, SiteCreate, SiteStatus,
            Tunnel, TunnelStats,
            TrafficStats, ThreatStats
        )
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "users", description = "User management"),
        (name = "policies", description = "Access policy management"),
        (name = "sites", description = "Site/edge management"),
        (name = "tunnels", description = "Tunnel management"),
        (name = "analytics", description = "Analytics and reporting")
    )
)]
pub struct ApiDoc;

/// Build the API router
pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(routes::health::health_check))
        .nest("/api/v1", api_routes())
        .layer(CorsLayer::permissive())
        .layer(middleware::auth::auth_layer())
        .layer(middleware::rate_limit::rate_limit_layer())
        .with_state(Arc::new(state))
}

fn api_routes() -> Router<Arc<ApiState>> {
    Router::new()
        // Tenant-scoped resources
        .nest("/tenants/:tenant_id/users", routes::users::router())
        .nest("/tenants/:tenant_id/policies", routes::policies::router())
        .nest("/tenants/:tenant_id/sites", routes::sites::router())
        .nest("/tenants/:tenant_id/tunnels", routes::tunnels::router())
        .nest("/tenants/:tenant_id/apps", routes::apps::router())
        .nest("/tenants/:tenant_id/alerts", routes::alerts::router())
        .nest("/tenants/:tenant_id/analytics", routes::analytics::router())
        // Global resources
        .nest("/webhooks", routes::webhooks::router())
        .nest("/api-keys", routes::api_keys::router())
}
