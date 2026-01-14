//! Authentication middleware

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::StatusCode,
};
use tower::Layer;

/// Auth layer (stub - returns identity layer)
pub fn auth_layer() -> tower::util::Identity {
    tower::util::Identity::new()
}

/// Verify API key
pub fn verify_api_key(key: &str) -> Option<ApiKeyInfo> {
    // In production: lookup in database
    if key.starts_with("ops_live_") || key.starts_with("ops_test_") {
        Some(ApiKeyInfo {
            key_id: "key_123".into(),
            tenant_id: "tenant_abc".into(),
            scopes: vec!["read:all".into(), "write:policies".into()],
        })
    } else {
        None
    }
}

/// Verify JWT token
pub fn verify_jwt(token: &str) -> Option<JwtClaims> {
    // In production: verify with jsonwebtoken
    if !token.is_empty() {
        Some(JwtClaims {
            sub: "user_123".into(),
            email: "user@example.com".into(),
            tenant_id: "tenant_abc".into(),
            roles: vec!["admin".into()],
            exp: chrono::Utc::now().timestamp() as usize + 3600,
        })
    } else {
        None
    }
}

/// API key info
#[derive(Debug, Clone)]
pub struct ApiKeyInfo {
    pub key_id: String,
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

/// JWT claims
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub email: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
    pub exp: usize,
}

/// Scopes for authorization
pub mod scopes {
    pub const READ_ALL: &str = "read:all";
    pub const WRITE_USERS: &str = "write:users";
    pub const WRITE_POLICIES: &str = "write:policies";
    pub const WRITE_SITES: &str = "write:sites";
    pub const ADMIN: &str = "admin";
}
