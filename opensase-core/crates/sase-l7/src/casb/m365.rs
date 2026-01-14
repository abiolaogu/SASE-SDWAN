//! Microsoft 365 CASB Connector
//!
//! Integrates with Microsoft Graph API for O365/Azure AD.

use crate::casb::{AuditEvent, RiskySignin, SaaSConnector, SaaSUser, SharedFile};
use crate::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, debug};

/// Microsoft 365 connector
pub struct M365Connector {
    client: Client,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    access_token: tokio::sync::RwLock<Option<String>>,
}

impl M365Connector {
    /// Create new M365 connector
    pub fn new(tenant_id: &str, client_id: &str, client_secret: &str) -> Self {
        Self {
            client: Client::new(),
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            access_token: tokio::sync::RwLock::new(None),
        }
    }
    
    /// Get access token
    async fn get_token(&self) -> Result<String> {
        // Check cached token
        {
            let token = self.access_token.read().await;
            if let Some(ref t) = *token {
                return Ok(t.clone());
            }
        }
        
        // Get new token
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );
        
        let params = [
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", &"https://graph.microsoft.com/.default".to_string()),
            ("grant_type", &"client_credentials".to_string()),
        ];
        
        let response: TokenResponse = self.client
            .post(&token_url)
            .form(&params)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| crate::L7Error::CasbError(e.to_string()))?;
        
        // Cache token
        {
            let mut token = self.access_token.write().await;
            *token = Some(response.access_token.clone());
        }
        
        Ok(response.access_token)
    }
    
    /// Make authenticated Graph API request
    async fn graph_request<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let token = self.get_token().await?;
        
        let response = self.client
            .get(url)
            .bearer_auth(&token)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| crate::L7Error::CasbError(e.to_string()))?;
        
        Ok(response)
    }
}

#[async_trait]
impl SaaSConnector for M365Connector {
    fn provider(&self) -> &'static str {
        "microsoft365"
    }
    
    async fn get_audit_logs(&self, since: DateTime<Utc>) -> Result<Vec<AuditEvent>> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/auditLogs/signIns?\
            $filter=createdDateTime ge {}&\
            $orderby=createdDateTime desc&\
            $top=100",
            since.to_rfc3339()
        );
        
        let response: GraphResponse<SignIn> = self.graph_request(&url).await?;
        
        Ok(response.value.into_iter().map(|s| AuditEvent {
            id: s.id,
            timestamp: s.created_date_time,
            user_id: s.user_id,
            user_email: s.user_principal_name,
            action: "signin".to_string(),
            resource: s.app_display_name,
            source_ip: s.ip_address,
            location: s.location.map(|l| format!("{}, {}", l.city.unwrap_or_default(), l.country_or_region.unwrap_or_default())),
            success: s.status.error_code == 0,
            details: serde_json::json!({
                "client_app": s.client_app_used,
                "device": s.device_detail,
            }),
        }).collect())
    }
    
    async fn get_users(&self) -> Result<Vec<SaaSUser>> {
        let url = "https://graph.microsoft.com/v1.0/users?\
            $select=id,mail,displayName,accountEnabled,signInActivity";
        
        let response: GraphResponse<GraphUser> = self.graph_request(url).await?;
        
        Ok(response.value.into_iter().map(|u| SaaSUser {
            id: u.id,
            email: u.mail.unwrap_or_default(),
            display_name: u.display_name,
            status: if u.account_enabled { "active" } else { "disabled" }.to_string(),
            last_login: u.sign_in_activity.and_then(|a| a.last_sign_in_date_time),
            risk_level: None,
        }).collect())
    }
    
    async fn get_risky_signins(&self) -> Result<Vec<RiskySignin>> {
        let url = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\
            $filter=riskLevel ne 'none'";
        
        let response: GraphResponse<RiskyUser> = self.graph_request(url).await?;
        
        Ok(response.value.into_iter().map(|u| RiskySignin {
            user_id: u.id.clone(),
            user_email: u.user_principal_name,
            risk_level: u.risk_level,
            risk_detail: u.risk_detail.unwrap_or_default(),
            signin_time: u.risk_last_updated_date_time.unwrap_or_else(Utc::now),
            source_ip: None,
            location: None,
        }).collect())
    }
    
    async fn get_shared_files(&self) -> Result<Vec<SharedFile>> {
        // Would query OneDrive/SharePoint sharing permissions
        Ok(Vec::new())
    }
    
    async fn revoke_session(&self, user_id: &str) -> Result<()> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/users/{}/revokeSignInSessions",
            user_id
        );
        
        let token = self.get_token().await?;
        
        self.client
            .post(&url)
            .bearer_auth(&token)
            .send()
            .await?;
        
        info!("Revoked M365 sessions for user {}", user_id);
        Ok(())
    }
    
    async fn block_user(&self, user_id: &str) -> Result<()> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/users/{}",
            user_id
        );
        
        let token = self.get_token().await?;
        
        self.client
            .patch(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "accountEnabled": false
            }))
            .send()
            .await?;
        
        info!("Disabled M365 user {}", user_id);
        Ok(())
    }
}

// Graph API types

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct GraphResponse<T> {
    value: Vec<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignIn {
    id: String,
    created_date_time: DateTime<Utc>,
    user_id: String,
    user_principal_name: String,
    app_display_name: String,
    ip_address: Option<String>,
    location: Option<SignInLocation>,
    status: SignInStatus,
    client_app_used: Option<String>,
    device_detail: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInLocation {
    city: Option<String>,
    country_or_region: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInStatus {
    error_code: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphUser {
    id: String,
    mail: Option<String>,
    display_name: String,
    account_enabled: bool,
    sign_in_activity: Option<SignInActivity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInActivity {
    last_sign_in_date_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RiskyUser {
    id: String,
    user_principal_name: String,
    risk_level: String,
    risk_detail: Option<String>,
    risk_last_updated_date_time: Option<DateTime<Utc>>,
}
