//! Authentication Manager
//!
//! Device authentication and token management.

use serde::{Deserialize, Serialize};

pub struct AuthManager {
    server_url: String,
    tenant_id: String,
    client: reqwest::Client,
    token: parking_lot::RwLock<Option<AuthToken>>,
    device_id: parking_lot::RwLock<Option<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub token_type: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthResult {
    pub token: String,
    pub device_id: String,
    pub user_id: Option<String>,
    pub enrolled: bool,
}

#[derive(Clone, Debug, Serialize)]
struct DeviceAuthRequest {
    device_id: String,
    device_name: String,
    platform: String,
    os_version: String,
    client_version: String,
    tenant_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeviceAuthResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    device_enrolled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TunnelConfigResponse {
    pub server_endpoint: String,
    pub server_public_key: String,
    pub client_private_key: String,
    pub client_ip: String,
    pub dns_servers: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub mtu: u16,
    pub keepalive: u16,
    pub policies: Vec<crate::policy::Policy>,
}

impl AuthManager {
    pub fn new(server_url: &str, tenant_id: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            tenant_id: tenant_id.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
            token: parking_lot::RwLock::new(None),
            device_id: parking_lot::RwLock::new(None),
        }
    }
    
    pub async fn authenticate(&self) -> Result<AuthResult, AuthError> {
        let device_id = self.get_or_create_device_id();
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        
        let request = DeviceAuthRequest {
            device_id: device_id.clone(),
            device_name: hostname,
            platform: std::env::consts::OS.to_string(),
            os_version: crate::PlatformInfo::detect().os_version,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            tenant_id: self.tenant_id.clone(),
        };
        
        let response = self.client
            .post(&format!("{}/api/v1/device/auth", self.server_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(AuthError::AuthFailed(format!(
                "Server returned {}",
                response.status()
            )));
        }
        
        let auth_response: DeviceAuthResponse = response.json().await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;
        
        let token = AuthToken {
            access_token: auth_response.access_token.clone(),
            refresh_token: auth_response.refresh_token,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(auth_response.expires_in as i64),
            token_type: "Bearer".to_string(),
        };
        
        *self.token.write() = Some(token);
        
        Ok(AuthResult {
            token: auth_response.access_token,
            device_id,
            user_id: None,
            enrolled: auth_response.device_enrolled,
        })
    }
    
    pub async fn get_tunnel_config(&self, token: &str) -> Result<crate::tunnel::TunnelConfig, AuthError> {
        let response = self.client
            .get(&format!("{}/api/v1/device/tunnel-config", self.server_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(AuthError::ConfigError(format!(
                "Server returned {}",
                response.status()
            )));
        }
        
        let config: TunnelConfigResponse = response.json().await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;
        
        Ok(crate::tunnel::TunnelConfig {
            server_endpoint: config.server_endpoint,
            server_public_key: config.server_public_key,
            client_private_key: config.client_private_key,
            client_ip: config.client_ip,
            dns_servers: config.dns_servers,
            allowed_ips: config.allowed_ips,
            mtu: config.mtu,
            keepalive: config.keepalive,
            policies: config.policies,
        })
    }
    
    pub async fn refresh_token(&self) -> Result<(), AuthError> {
        let current_token = self.token.read().clone()
            .ok_or(AuthError::NoToken)?;
        
        let response = self.client
            .post(&format!("{}/api/v1/device/refresh", self.server_url))
            .json(&serde_json::json!({
                "refresh_token": current_token.refresh_token
            }))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(AuthError::RefreshFailed);
        }
        
        let new_token: DeviceAuthResponse = response.json().await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;
        
        *self.token.write() = Some(AuthToken {
            access_token: new_token.access_token,
            refresh_token: new_token.refresh_token,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(new_token.expires_in as i64),
            token_type: "Bearer".to_string(),
        });
        
        Ok(())
    }
    
    pub fn get_token(&self) -> Option<String> {
        self.token.read().as_ref().map(|t| t.access_token.clone())
    }
    
    pub fn is_token_valid(&self) -> bool {
        if let Some(token) = self.token.read().as_ref() {
            token.expires_at > chrono::Utc::now()
        } else {
            false
        }
    }
    
    fn get_or_create_device_id(&self) -> String {
        if let Some(id) = self.device_id.read().clone() {
            return id;
        }
        
        // Try to load from persistent storage
        if let Some(id) = self.load_device_id() {
            *self.device_id.write() = Some(id.clone());
            return id;
        }
        
        // Generate new device ID
        let id = uuid::Uuid::new_v4().to_string();
        self.save_device_id(&id);
        *self.device_id.write() = Some(id.clone());
        id
    }
    
    fn load_device_id(&self) -> Option<String> {
        // Platform-specific persistent storage
        #[cfg(target_os = "windows")]
        {
            // Load from Windows Registry
            None
        }
        #[cfg(target_os = "macos")]
        {
            // Load from Keychain
            None
        }
        #[cfg(target_os = "linux")]
        {
            // Load from ~/.config/opensase
            let path = dirs::config_dir()?.join("opensase/device_id");
            std::fs::read_to_string(path).ok()
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }
    
    fn save_device_id(&self, id: &str) {
        #[cfg(target_os = "linux")]
        {
            if let Some(config_dir) = dirs::config_dir() {
                let path = config_dir.join("opensase");
                let _ = std::fs::create_dir_all(&path);
                let _ = std::fs::write(path.join("device_id"), id);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Config error: {0}")]
    ConfigError(String),
    
    #[error("No token available")]
    NoToken,
    
    #[error("Token refresh failed")]
    RefreshFailed,
}
