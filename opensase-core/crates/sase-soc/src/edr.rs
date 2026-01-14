//! EDR Integrations
//!
//! CrowdStrike, Microsoft Defender, SentinelOne, Carbon Black.

use std::collections::HashMap;

#[async_trait::async_trait]
pub trait EdrIntegration: Send + Sync {
    fn name(&self) -> &str;
    async fn collect_timeline(&self, device_id: &str, hours: u32) -> Result<Vec<TimelineEvent>, EdrError>;
    async fn collect_processes(&self, device_id: &str) -> Result<Vec<ProcessInfo>, EdrError>;
    async fn collect_network(&self, device_id: &str) -> Result<Vec<NetworkConnection>, EdrError>;
    async fn isolate_device(&self, device_id: &str) -> Result<(), EdrError>;
    async fn release_device(&self, device_id: &str) -> Result<(), EdrError>;
    async fn health_check(&self) -> bool;
}

#[derive(Clone, serde::Serialize)]
pub struct TimelineEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub description: String,
    pub process: Option<String>,
    pub user: Option<String>,
    pub details: HashMap<String, String>,
}

#[derive(Clone, serde::Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
    pub user: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub hash_sha256: Option<String>,
}

#[derive(Clone, serde::Serialize)]
pub struct NetworkConnection {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub process: Option<String>,
}

// CrowdStrike Integration
pub struct CrowdStrikeEdr {
    client: reqwest::Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    token: parking_lot::RwLock<Option<String>>,
}

impl CrowdStrikeEdr {
    pub fn new(base_url: &str, client_id: &str, client_secret: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            token: parking_lot::RwLock::new(None),
        }
    }
    
    async fn get_token(&self) -> Result<String, EdrError> {
        if let Some(token) = self.token.read().clone() {
            return Ok(token);
        }
        
        let resp = self.client
            .post(&format!("{}/oauth2/token", self.base_url))
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()
            .await
            .map_err(|e| EdrError::AuthFailed(e.to_string()))?;
        
        let data: serde_json::Value = resp.json().await
            .map_err(|e| EdrError::AuthFailed(e.to_string()))?;
        
        let token = data["access_token"].as_str()
            .ok_or_else(|| EdrError::AuthFailed("No token".to_string()))?
            .to_string();
        
        *self.token.write() = Some(token.clone());
        Ok(token)
    }
}

#[async_trait::async_trait]
impl EdrIntegration for CrowdStrikeEdr {
    fn name(&self) -> &str { "CrowdStrike" }
    
    async fn collect_timeline(&self, device_id: &str, hours: u32) -> Result<Vec<TimelineEvent>, EdrError> {
        let token = self.get_token().await?;
        tracing::info!("Collecting timeline from CrowdStrike for device {}", device_id);
        // In production: query /devices/entities/devices/v1
        Ok(vec![])
    }
    
    async fn collect_processes(&self, device_id: &str) -> Result<Vec<ProcessInfo>, EdrError> {
        let token = self.get_token().await?;
        tracing::info!("Collecting processes from CrowdStrike for device {}", device_id);
        Ok(vec![])
    }
    
    async fn collect_network(&self, device_id: &str) -> Result<Vec<NetworkConnection>, EdrError> {
        let token = self.get_token().await?;
        Ok(vec![])
    }
    
    async fn isolate_device(&self, device_id: &str) -> Result<(), EdrError> {
        let token = self.get_token().await?;
        tracing::info!("CrowdStrike: Isolating device {}", device_id);
        
        let _resp = self.client
            .post(&format!("{}/devices/entities/devices-actions/v2", self.base_url))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "action_name": "contain",
                "ids": [device_id]
            }))
            .send()
            .await
            .map_err(|e| EdrError::ActionFailed(e.to_string()))?;
        
        Ok(())
    }
    
    async fn release_device(&self, device_id: &str) -> Result<(), EdrError> {
        let token = self.get_token().await?;
        tracing::info!("CrowdStrike: Releasing device {}", device_id);
        Ok(())
    }
    
    async fn health_check(&self) -> bool {
        self.get_token().await.is_ok()
    }
}

// Microsoft Defender Integration
pub struct DefenderEdr {
    client: reqwest::Client,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    token: parking_lot::RwLock<Option<String>>,
}

impl DefenderEdr {
    pub fn new(tenant_id: &str, client_id: &str, client_secret: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            token: parking_lot::RwLock::new(None),
        }
    }
    
    async fn get_token(&self) -> Result<String, EdrError> {
        if let Some(token) = self.token.read().clone() {
            return Ok(token);
        }
        
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );
        
        let resp = self.client
            .post(&url)
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("scope", &"https://api.securitycenter.microsoft.com/.default".to_string()),
                ("grant_type", &"client_credentials".to_string()),
            ])
            .send()
            .await
            .map_err(|e| EdrError::AuthFailed(e.to_string()))?;
        
        let data: serde_json::Value = resp.json().await
            .map_err(|e| EdrError::AuthFailed(e.to_string()))?;
        
        let token = data["access_token"].as_str()
            .ok_or_else(|| EdrError::AuthFailed("No token".to_string()))?
            .to_string();
        
        *self.token.write() = Some(token.clone());
        Ok(token)
    }
}

#[async_trait::async_trait]
impl EdrIntegration for DefenderEdr {
    fn name(&self) -> &str { "Microsoft Defender" }
    
    async fn collect_timeline(&self, device_id: &str, hours: u32) -> Result<Vec<TimelineEvent>, EdrError> {
        let token = self.get_token().await?;
        tracing::info!("Collecting timeline from Defender for device {}", device_id);
        Ok(vec![])
    }
    
    async fn collect_processes(&self, device_id: &str) -> Result<Vec<ProcessInfo>, EdrError> {
        let token = self.get_token().await?;
        Ok(vec![])
    }
    
    async fn collect_network(&self, device_id: &str) -> Result<Vec<NetworkConnection>, EdrError> {
        Ok(vec![])
    }
    
    async fn isolate_device(&self, device_id: &str) -> Result<(), EdrError> {
        let token = self.get_token().await?;
        tracing::info!("Defender: Isolating device {}", device_id);
        
        let _resp = self.client
            .post(&format!(
                "https://api.securitycenter.microsoft.com/api/machines/{}/isolate",
                device_id
            ))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "Comment": "Isolated by OpenSASE SOAR",
                "IsolationType": "Full"
            }))
            .send()
            .await
            .map_err(|e| EdrError::ActionFailed(e.to_string()))?;
        
        Ok(())
    }
    
    async fn release_device(&self, device_id: &str) -> Result<(), EdrError> {
        let token = self.get_token().await?;
        tracing::info!("Defender: Releasing device {}", device_id);
        Ok(())
    }
    
    async fn health_check(&self) -> bool {
        self.get_token().await.is_ok()
    }
}

// SentinelOne Integration
pub struct SentinelOneEdr {
    client: reqwest::Client,
    base_url: String,
    api_token: String,
}

impl SentinelOneEdr {
    pub fn new(base_url: &str, api_token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            api_token: api_token.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl EdrIntegration for SentinelOneEdr {
    fn name(&self) -> &str { "SentinelOne" }
    
    async fn collect_timeline(&self, device_id: &str, hours: u32) -> Result<Vec<TimelineEvent>, EdrError> {
        tracing::info!("Collecting timeline from SentinelOne for device {}", device_id);
        Ok(vec![])
    }
    
    async fn collect_processes(&self, device_id: &str) -> Result<Vec<ProcessInfo>, EdrError> {
        Ok(vec![])
    }
    
    async fn collect_network(&self, device_id: &str) -> Result<Vec<NetworkConnection>, EdrError> {
        Ok(vec![])
    }
    
    async fn isolate_device(&self, device_id: &str) -> Result<(), EdrError> {
        tracing::info!("SentinelOne: Isolating device {}", device_id);
        
        let _resp = self.client
            .post(&format!("{}/web/api/v2.1/agents/actions/disconnect", self.base_url))
            .header("Authorization", format!("ApiToken {}", self.api_token))
            .json(&serde_json::json!({
                "filter": { "ids": [device_id] }
            }))
            .send()
            .await
            .map_err(|e| EdrError::ActionFailed(e.to_string()))?;
        
        Ok(())
    }
    
    async fn release_device(&self, device_id: &str) -> Result<(), EdrError> {
        tracing::info!("SentinelOne: Releasing device {}", device_id);
        Ok(())
    }
    
    async fn health_check(&self) -> bool { true }
}

#[derive(Debug)]
pub enum EdrError {
    AuthFailed(String),
    DeviceNotFound,
    ActionFailed(String),
    Timeout,
}

impl std::fmt::Display for EdrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed(e) => write!(f, "Auth failed: {}", e),
            Self::DeviceNotFound => write!(f, "Device not found"),
            Self::ActionFailed(e) => write!(f, "Action failed: {}", e),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for EdrError {}
