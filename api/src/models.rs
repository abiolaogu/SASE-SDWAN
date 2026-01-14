//! API Models

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Standard API response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ErrorResponse>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self { success: true, data: Some(data), error: None }
    }

    pub fn error(code: &str, message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ErrorResponse {
                code: code.to_string(),
                message: message.to_string(),
            }),
        }
    }
}

/// Error response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

/// Paginated response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

// ============ Users ============

/// User
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub mfa_enabled: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

/// User creation request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserCreate {
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub send_invite: bool,
}

/// User role
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum UserRole {
    Admin,
    Editor,
    Viewer,
    ServiceAccount,
}

// ============ Policies ============

/// Access policy
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub conditions: Vec<PolicyCondition>,
    pub action: PolicyAction,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Policy creation request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PolicyCreate {
    pub name: String,
    pub description: String,
    pub priority: u32,
    pub conditions: Vec<PolicyCondition>,
    pub action: PolicyAction,
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

/// Policy action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum PolicyAction {
    Allow,
    Block,
    Isolate,
    Log,
}

// ============ Sites ============

/// Site (edge location)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Site {
    pub id: Uuid,
    pub name: String,
    pub location: String,
    pub status: SiteStatus,
    pub edge_count: u32,
    pub user_count: u32,
    pub created_at: DateTime<Utc>,
}

/// Site creation request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SiteCreate {
    pub name: String,
    pub location: String,
    pub timezone: String,
}

/// Site status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum SiteStatus {
    Active,
    Degraded,
    Offline,
    Provisioning,
}

// ============ Tunnels ============

/// Tunnel
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Tunnel {
    pub id: Uuid,
    pub name: String,
    pub tunnel_type: String,
    pub status: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub created_at: DateTime<Utc>,
}

/// Tunnel statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TunnelStats {
    pub tunnel_id: Uuid,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss_percent: f32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub uptime_seconds: u64,
}

// ============ Analytics ============

/// Traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TrafficStats {
    pub period: String,
    pub total_bytes: u64,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub top_applications: Vec<AppUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AppUsage {
    pub name: String,
    pub bytes: u64,
    pub percentage: f32,
}

/// Threat statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ThreatStats {
    pub period: String,
    pub total_threats: u64,
    pub by_category: Vec<ThreatCategory>,
    pub top_blocked_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ThreatCategory {
    pub name: String,
    pub count: u64,
}

// ============ Webhooks ============

/// Webhook subscription
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Webhook {
    pub id: Uuid,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// Webhook creation
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct WebhookCreate {
    pub url: String,
    pub events: Vec<String>,
}

// ============ API Keys ============

/// API Key
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// API Key creation
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyCreate {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<u32>,
}

/// API Key creation response (includes full key)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyCreated {
    pub id: Uuid,
    pub name: String,
    pub key: String, // Only shown once
    pub scopes: Vec<String>,
}
