//! Identity domain types
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::Metadata;

/// User entity
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default)]
    pub profile: Option<UserProfile>,
    pub status: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub metadata: Metadata,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User profile
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UserProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Create user params
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateUserParams {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<UserProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_welcome_email: Option<bool>,
}

impl CreateUserParams {
    pub fn builder() -> CreateUserParamsBuilder { CreateUserParamsBuilder::default() }
}

#[derive(Debug, Clone, Default)]
pub struct CreateUserParamsBuilder { params: CreateUserParams }

impl CreateUserParamsBuilder {
    pub fn email(mut self, email: impl Into<String>) -> Self { self.params.email = email.into(); self }
    pub fn password(mut self, pw: impl Into<String>) -> Self { self.params.password = Some(pw.into()); self }
    pub fn profile(mut self, p: UserProfile) -> Self { self.params.profile = Some(p); self }
    pub fn build(self) -> CreateUserParams { self.params }
}

/// Login response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: User,
}
