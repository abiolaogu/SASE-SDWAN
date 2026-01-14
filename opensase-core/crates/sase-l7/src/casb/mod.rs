//! CASB Module - Cloud Access Security Broker
//!
//! SaaS application connectors for visibility and control.

mod service;
mod m365;
mod google;

pub use service::CasbService;
pub use m365::M365Connector;
pub use google::GoogleWorkspaceConnector;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::Result;

/// Audit event from SaaS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub user_email: String,
    pub action: String,
    pub resource: String,
    pub source_ip: Option<String>,
    pub location: Option<String>,
    pub success: bool,
    pub details: serde_json::Value,
}

/// SaaS user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaaSUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub last_login: Option<DateTime<Utc>>,
    pub risk_level: Option<String>,
}

/// Risky sign-in
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskySignin {
    pub user_id: String,
    pub user_email: String,
    pub risk_level: String,
    pub risk_detail: String,
    pub signin_time: DateTime<Utc>,
    pub source_ip: Option<String>,
    pub location: Option<String>,
}

/// Shared file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFile {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub shared_with: Vec<String>,
    pub external_share: bool,
    pub link_type: String,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

/// SaaS connector trait
#[async_trait]
pub trait SaaSConnector: Send + Sync {
    /// Get provider name
    fn provider(&self) -> &'static str;
    
    /// Get audit logs since timestamp
    async fn get_audit_logs(&self, since: DateTime<Utc>) -> Result<Vec<AuditEvent>>;
    
    /// Get all users
    async fn get_users(&self) -> Result<Vec<SaaSUser>>;
    
    /// Get risky sign-ins
    async fn get_risky_signins(&self) -> Result<Vec<RiskySignin>>;
    
    /// Get shared files
    async fn get_shared_files(&self) -> Result<Vec<SharedFile>>;
    
    /// Revoke user session
    async fn revoke_session(&self, user_id: &str) -> Result<()>;
    
    /// Block user
    async fn block_user(&self, user_id: &str) -> Result<()>;
}

/// SaaS provider enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaaSProvider {
    Microsoft365,
    GoogleWorkspace,
    Salesforce,
    Slack,
    Zoom,
    Dropbox,
    Box,
    GitHub,
}

impl SaaSProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            SaaSProvider::Microsoft365 => "microsoft365",
            SaaSProvider::GoogleWorkspace => "google-workspace",
            SaaSProvider::Salesforce => "salesforce",
            SaaSProvider::Slack => "slack",
            SaaSProvider::Zoom => "zoom",
            SaaSProvider::Dropbox => "dropbox",
            SaaSProvider::Box => "box",
            SaaSProvider::GitHub => "github",
        }
    }
}
