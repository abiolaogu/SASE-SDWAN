//! OpenSASE Portal API Backend
//!
//! Rust/Axum API gateway for the management portal.

use axum::{
    extract::{Path, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

mod models;
mod handlers;
mod auth;
mod ws;

use handlers::*;

#[derive(Clone)]
pub struct AppState {
    pub sites: Arc<RwLock<Vec<models::Site>>>,
    pub users: Arc<RwLock<Vec<models::User>>>,
    pub apps: Arc<RwLock<Vec<models::App>>>,
    pub policies: Arc<RwLock<Vec<models::Policy>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            sites: Arc::new(RwLock::new(models::mock_sites())),
            users: Arc::new(RwLock::new(models::mock_users())),
            apps: Arc::new(RwLock::new(models::mock_apps())),
            policies: Arc::new(RwLock::new(models::mock_policies())),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState::new();

    let app = Router::new()
        // Health check
        .route("/health", get(health))
        
        // Sites
        .route("/api/sites", get(list_sites).post(create_site))
        .route("/api/sites/:id", get(get_site).put(update_site).delete(delete_site))
        
        // Users
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:id", get(get_user).put(update_user).delete(delete_user))
        
        // Apps
        .route("/api/apps", get(list_apps).post(create_app))
        .route("/api/apps/:id", get(get_app).put(update_app).delete(delete_app))
        
        // Policies
        .route("/api/policies", get(list_policies).post(create_policy))
        .route("/api/policies/:id", get(get_policy).put(update_policy).delete(delete_policy))
        
        // Analytics
        .route("/api/analytics/overview", get(analytics_overview))
        .route("/api/analytics/traffic", get(analytics_traffic))
        .route("/api/analytics/security", get(analytics_security))
        
        // WebSocket
        .route("/ws", get(ws_handler))
        
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = "0.0.0.0:8080";
    tracing::info!("Portal API listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "OK"
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| ws::handle_socket(socket, state))
}
