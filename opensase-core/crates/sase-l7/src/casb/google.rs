//! Google Workspace CASB Connector
//!
//! Integrates with Google Admin SDK and Drive API.

use crate::casb::{AuditEvent, RiskySignin, SaaSConnector, SaaSUser, SharedFile};
use crate::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, debug};

/// Google Workspace connector
pub struct GoogleWorkspaceConnector {
    client: Client,
    service_account_email: String,
    private_key: String,
    admin_email: String,
    access_token: tokio::sync::RwLock<Option<String>>,
}

impl GoogleWorkspaceConnector {
    /// Create new Google Workspace connector
    pub fn new(service_account_email: &str, private_key: &str, admin_email: &str) -> Self {
        Self {
            client: Client::new(),
            service_account_email: service_account_email.to_string(),
            private_key: private_key.to_string(),
            admin_email: admin_email.to_string(),
            access_token: tokio::sync::RwLock::new(None),
        }
    }
    
    /// Get access token via service account JWT
    async fn get_token(&self) -> Result<String> {
        // Check cached token
        {
            let token = self.access_token.read().await;
            if let Some(ref t) = *token {
                return Ok(t.clone());
            }
        }
        
        // In production, would create JWT and exchange for access token
        // Using Google's OAuth 2.0 service account flow
        
        // Placeholder - would use jsonwebtoken crate
        let access_token = "google_access_token".to_string();
        
        {
            let mut token = self.access_token.write().await;
            *token = Some(access_token.clone());
        }
        
        Ok(access_token)
    }
    
    /// Make authenticated API request
    async fn api_request<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
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
impl SaaSConnector for GoogleWorkspaceConnector {
    fn provider(&self) -> &'static str {
        "google-workspace"
    }
    
    async fn get_audit_logs(&self, since: DateTime<Utc>) -> Result<Vec<AuditEvent>> {
        let url = format!(
            "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?\
            startTime={}",
            since.to_rfc3339()
        );
        
        let response: AdminReportsResponse = self.api_request(&url).await?;
        
        Ok(response.items.unwrap_or_default().into_iter().map(|item| {
            let events = item.events.unwrap_or_default();
            let first_event = events.first();
            
            let activity_id = item.id.unwrap_or_default();
            let unique_id = activity_id.unique_qualifier.clone().unwrap_or_default();
            let timestamp = activity_id.time.unwrap_or_else(Utc::now);
            
            AuditEvent {
                id: unique_id,
                timestamp,
                user_id: item.actor.as_ref().and_then(|a| a.profile_id.clone()).unwrap_or_default(),
                user_email: item.actor.as_ref().and_then(|a| a.email.clone()).unwrap_or_default(),
                action: first_event.map(|e| e.name.clone()).unwrap_or_default(),
                resource: "login".to_string(),
                source_ip: item.ip_address,
                location: None,
                success: first_event.map(|e| e.name != "login_failure").unwrap_or(true),
                details: serde_json::json!({}),
            }
        }).collect())
    }
    
    async fn get_users(&self) -> Result<Vec<SaaSUser>> {
        let url = "https://admin.googleapis.com/admin/directory/v1/users?\
            customer=my_customer&maxResults=100";
        
        let response: DirectoryUsersResponse = self.api_request(url).await?;
        
        Ok(response.users.unwrap_or_default().into_iter().map(|u| SaaSUser {
            id: u.id,
            email: u.primary_email,
            display_name: u.name.full_name,
            status: if u.suspended { "suspended" } else { "active" }.to_string(),
            last_login: u.last_login_time,
            risk_level: None,
        }).collect())
    }
    
    async fn get_risky_signins(&self) -> Result<Vec<RiskySignin>> {
        // Google doesn't have a direct risky signin API like Azure AD
        // Would analyze login events for suspicious patterns
        Ok(Vec::new())
    }
    
    async fn get_shared_files(&self) -> Result<Vec<SharedFile>> {
        let url = "https://www.googleapis.com/drive/v3/files?\
            q=visibility='anyoneWithLink' or visibility='domainWithLink'&\
            fields=files(id,name,owners,permissions,createdTime,modifiedTime)";
        
        let response: DriveFilesResponse = self.api_request(url).await?;
        
        Ok(response.files.unwrap_or_default().into_iter().map(|f| {
            let permissions = f.permissions.unwrap_or_default();
            let external_share = permissions.iter().any(|p| p.type_ == "anyone");
            let shared_with: Vec<String> = permissions.iter()
                .filter_map(|p| p.email_address.clone())
                .collect();
            
            SharedFile {
                id: f.id,
                name: f.name,
                owner: f.owners.and_then(|o| o.first().map(|u| u.email_address.clone())).unwrap_or_default(),
                shared_with,
                external_share,
                link_type: if external_share { "anyone" } else { "domain" }.to_string(),
                created_at: f.created_time.unwrap_or_else(Utc::now),
                modified_at: f.modified_time.unwrap_or_else(Utc::now),
            }
        }).collect())
    }
    
    async fn revoke_session(&self, user_id: &str) -> Result<()> {
        let url = format!(
            "https://admin.googleapis.com/admin/directory/v1/users/{}/signOut",
            user_id
        );
        
        let token = self.get_token().await?;
        
        self.client
            .post(&url)
            .bearer_auth(&token)
            .send()
            .await?;
        
        info!("Signed out Google user {}", user_id);
        Ok(())
    }
    
    async fn block_user(&self, user_id: &str) -> Result<()> {
        let url = format!(
            "https://admin.googleapis.com/admin/directory/v1/users/{}",
            user_id
        );
        
        let token = self.get_token().await?;
        
        self.client
            .put(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "suspended": true
            }))
            .send()
            .await?;
        
        info!("Suspended Google user {}", user_id);
        Ok(())
    }
}

// Google API types

#[derive(Debug, Deserialize)]
struct AdminReportsResponse {
    items: Option<Vec<ActivityItem>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityItem {
    id: Option<ActivityId>,
    actor: Option<Actor>,
    ip_address: Option<String>,
    events: Option<Vec<Event>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityId {
    time: Option<DateTime<Utc>>,
    unique_qualifier: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Actor {
    email: Option<String>,
    profile_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Event {
    name: String,
}

#[derive(Debug, Deserialize)]
struct DirectoryUsersResponse {
    users: Option<Vec<DirectoryUser>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryUser {
    id: String,
    primary_email: String,
    name: UserName,
    suspended: bool,
    last_login_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserName {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct DriveFilesResponse {
    files: Option<Vec<DriveFile>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveFile {
    id: String,
    name: String,
    owners: Option<Vec<FileOwner>>,
    permissions: Option<Vec<Permission>>,
    created_time: Option<DateTime<Utc>>,
    modified_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileOwner {
    email_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Permission {
    #[serde(rename = "type")]
    type_: String,
    email_address: Option<String>,
}
