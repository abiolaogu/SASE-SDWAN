//! API Handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;
use crate::{AppState, models::*};

// Sites
pub async fn list_sites(State(state): State<AppState>) -> Json<Vec<Site>> {
    let sites = state.sites.read().await;
    Json(sites.clone())
}

pub async fn get_site(Path(id): Path<Uuid>, State(state): State<AppState>) -> Result<Json<Site>, StatusCode> {
    let sites = state.sites.read().await;
    sites.iter().find(|s| s.id == id).cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_site(State(state): State<AppState>, Json(mut site): Json<Site>) -> (StatusCode, Json<Site>) {
    site.id = Uuid::new_v4();
    state.sites.write().await.push(site.clone());
    (StatusCode::CREATED, Json(site))
}

pub async fn update_site(Path(id): Path<Uuid>, State(state): State<AppState>, Json(update): Json<Site>) -> Result<Json<Site>, StatusCode> {
    let mut sites = state.sites.write().await;
    if let Some(site) = sites.iter_mut().find(|s| s.id == id) {
        *site = update.clone();
        Ok(Json(update))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn delete_site(Path(id): Path<Uuid>, State(state): State<AppState>) -> StatusCode {
    let mut sites = state.sites.write().await;
    sites.retain(|s| s.id != id);
    StatusCode::NO_CONTENT
}

// Users
pub async fn list_users(State(state): State<AppState>) -> Json<Vec<User>> {
    let users = state.users.read().await;
    Json(users.clone())
}

pub async fn get_user(Path(id): Path<Uuid>, State(state): State<AppState>) -> Result<Json<User>, StatusCode> {
    let users = state.users.read().await;
    users.iter().find(|u| u.id == id).cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_user(State(state): State<AppState>, Json(mut user): Json<User>) -> (StatusCode, Json<User>) {
    user.id = Uuid::new_v4();
    state.users.write().await.push(user.clone());
    (StatusCode::CREATED, Json(user))
}

pub async fn update_user(Path(id): Path<Uuid>, State(state): State<AppState>, Json(update): Json<User>) -> Result<Json<User>, StatusCode> {
    let mut users = state.users.write().await;
    if let Some(user) = users.iter_mut().find(|u| u.id == id) {
        *user = update.clone();
        Ok(Json(update))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn delete_user(Path(id): Path<Uuid>, State(state): State<AppState>) -> StatusCode {
    let mut users = state.users.write().await;
    users.retain(|u| u.id != id);
    StatusCode::NO_CONTENT
}

// Apps
pub async fn list_apps(State(state): State<AppState>) -> Json<Vec<App>> {
    let apps = state.apps.read().await;
    Json(apps.clone())
}

pub async fn get_app(Path(id): Path<Uuid>, State(state): State<AppState>) -> Result<Json<App>, StatusCode> {
    let apps = state.apps.read().await;
    apps.iter().find(|a| a.id == id).cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_app(State(state): State<AppState>, Json(mut app): Json<App>) -> (StatusCode, Json<App>) {
    app.id = Uuid::new_v4();
    state.apps.write().await.push(app.clone());
    (StatusCode::CREATED, Json(app))
}

pub async fn update_app(Path(id): Path<Uuid>, State(state): State<AppState>, Json(update): Json<App>) -> Result<Json<App>, StatusCode> {
    let mut apps = state.apps.write().await;
    if let Some(app) = apps.iter_mut().find(|a| a.id == id) {
        *app = update.clone();
        Ok(Json(update))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn delete_app(Path(id): Path<Uuid>, State(state): State<AppState>) -> StatusCode {
    let mut apps = state.apps.write().await;
    apps.retain(|a| a.id != id);
    StatusCode::NO_CONTENT
}

// Policies
pub async fn list_policies(State(state): State<AppState>) -> Json<Vec<Policy>> {
    let policies = state.policies.read().await;
    Json(policies.clone())
}

pub async fn get_policy(Path(id): Path<Uuid>, State(state): State<AppState>) -> Result<Json<Policy>, StatusCode> {
    let policies = state.policies.read().await;
    policies.iter().find(|p| p.id == id).cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_policy(State(state): State<AppState>, Json(mut policy): Json<Policy>) -> (StatusCode, Json<Policy>) {
    policy.id = Uuid::new_v4();
    state.policies.write().await.push(policy.clone());
    (StatusCode::CREATED, Json(policy))
}

pub async fn update_policy(Path(id): Path<Uuid>, State(state): State<AppState>, Json(update): Json<Policy>) -> Result<Json<Policy>, StatusCode> {
    let mut policies = state.policies.write().await;
    if let Some(policy) = policies.iter_mut().find(|p| p.id == id) {
        *policy = update.clone();
        Ok(Json(update))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn delete_policy(Path(id): Path<Uuid>, State(state): State<AppState>) -> StatusCode {
    let mut policies = state.policies.write().await;
    policies.retain(|p| p.id != id);
    StatusCode::NO_CONTENT
}

// Analytics
pub async fn analytics_overview() -> Json<AnalyticsOverview> {
    Json(AnalyticsOverview {
        total_bandwidth_tb: 4.2,
        active_sessions: 12847,
        threats_blocked: 1459,
        avg_response_ms: 23,
    })
}

pub async fn analytics_traffic() -> Json<Vec<TrafficData>> {
    let data: Vec<TrafficData> = (0..24).map(|h| TrafficData {
        hour: h,
        inbound_mb: 500 + (h as u64 * 50) % 400,
        outbound_mb: 300 + (h as u64 * 30) % 300,
    }).collect();
    Json(data)
}

pub async fn analytics_security() -> Json<Vec<SecurityEvent>> {
    Json(vec![
        SecurityEvent { id: Uuid::new_v4(), event_type: "blocked".into(), title: "Malware blocked".into(), source: "192.168.1.45".into(), time: "2m ago".into() },
        SecurityEvent { id: Uuid::new_v4(), event_type: "warning".into(), title: "Suspicious DNS query".into(), source: "10.0.0.23".into(), time: "5m ago".into() },
        SecurityEvent { id: Uuid::new_v4(), event_type: "blocked".into(), title: "IPS signature match".into(), source: "172.16.0.12".into(), time: "8m ago".into() },
    ])
}
