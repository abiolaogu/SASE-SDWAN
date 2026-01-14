//! Data Models

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: Uuid,
    pub name: String,
    pub location: String,
    pub status: String,
    pub users: u32,
    pub bandwidth: String,
    pub tunnels: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub devices: u32,
    pub last_active: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id: Uuid,
    pub name: String,
    pub app_type: String,
    pub host: String,
    pub status: String,
    pub users: u32,
    pub requests: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub policy_type: String,
    pub rules: u32,
    pub status: String,
    pub updated: String,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsOverview {
    pub total_bandwidth_tb: f64,
    pub active_sessions: u64,
    pub threats_blocked: u64,
    pub avg_response_ms: u32,
}

#[derive(Debug, Serialize)]
pub struct TrafficData {
    pub hour: u32,
    pub inbound_mb: u64,
    pub outbound_mb: u64,
}

#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub event_type: String,
    pub title: String,
    pub source: String,
    pub time: String,
}

// Mock data generators
pub fn mock_sites() -> Vec<Site> {
    vec![
        Site { id: Uuid::new_v4(), name: "HQ - New York".into(), location: "New York, USA".into(), status: "online".into(), users: 245, bandwidth: "1.2 Gbps".into(), tunnels: 3 },
        Site { id: Uuid::new_v4(), name: "London Office".into(), location: "London, UK".into(), status: "online".into(), users: 128, bandwidth: "850 Mbps".into(), tunnels: 2 },
        Site { id: Uuid::new_v4(), name: "Singapore DC".into(), location: "Singapore".into(), status: "warning".into(), users: 87, bandwidth: "420 Mbps".into(), tunnels: 2 },
        Site { id: Uuid::new_v4(), name: "Tokyo Office".into(), location: "Tokyo, Japan".into(), status: "online".into(), users: 156, bandwidth: "650 Mbps".into(), tunnels: 2 },
    ]
}

pub fn mock_users() -> Vec<User> {
    vec![
        User { id: Uuid::new_v4(), name: "John Smith".into(), email: "john@acme.com".into(), role: "Admin".into(), status: "active".into(), devices: 2, last_active: "5m ago".into() },
        User { id: Uuid::new_v4(), name: "Sarah Johnson".into(), email: "sarah@acme.com".into(), role: "User".into(), status: "active".into(), devices: 3, last_active: "1h ago".into() },
        User { id: Uuid::new_v4(), name: "Mike Brown".into(), email: "mike@acme.com".into(), role: "User".into(), status: "active".into(), devices: 1, last_active: "2h ago".into() },
    ]
}

pub fn mock_apps() -> Vec<App> {
    vec![
        App { id: Uuid::new_v4(), name: "Internal Wiki".into(), app_type: "HTTP".into(), host: "wiki.internal.acme.com".into(), status: "healthy".into(), users: 245, requests: "12.4K/day".into() },
        App { id: Uuid::new_v4(), name: "Git Server".into(), app_type: "SSH".into(), host: "git.internal.acme.com:22".into(), status: "healthy".into(), users: 87, requests: "8.2K/day".into() },
        App { id: Uuid::new_v4(), name: "Jenkins CI".into(), app_type: "HTTP".into(), host: "jenkins.internal.acme.com".into(), status: "healthy".into(), users: 56, requests: "5.6K/day".into() },
    ]
}

pub fn mock_policies() -> Vec<Policy> {
    vec![
        Policy { id: Uuid::new_v4(), name: "Default Outbound".into(), policy_type: "Firewall".into(), rules: 12, status: "active".into(), updated: "2h ago".into() },
        Policy { id: Uuid::new_v4(), name: "Block Malware".into(), policy_type: "IPS".into(), rules: 8, status: "active".into(), updated: "1d ago".into() },
        Policy { id: Uuid::new_v4(), name: "URL Categories".into(), policy_type: "URL Filter".into(), rules: 24, status: "active".into(), updated: "3d ago".into() },
    ]
}
