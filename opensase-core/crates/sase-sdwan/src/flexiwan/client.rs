//! FlexiWAN API Client
//!
//! REST API wrapper for FlexiWAN SD-WAN controller.

use crate::{Result, SdwanError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

/// FlexiWAN API Client
pub struct FlexiWanClient {
    /// API base URL
    base_url: String,
    /// HTTP client
    client: Client,
    /// Authentication token
    token: RwLock<Option<String>>,
    /// Current organization ID
    org_id: RwLock<Option<String>>,
}

impl FlexiWanClient {
    /// Create new FlexiWAN client
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            token: RwLock::new(None),
            org_id: RwLock::new(None),
        }
    }
    
    /// Authenticate with FlexiWAN
    pub async fn authenticate(&self, email: &str, password: &str) -> Result<()> {
        let url = format!("{}/api/auth/login", self.base_url);
        
        let response = self.client
            .post(&url)
            .json(&serde_json::json!({
                "email": email,
                "password": password
            }))
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(SdwanError::FlexiWanError("Authentication failed".to_string()));
        }
        
        let auth_response: AuthResponse = response.json().await
            .map_err(|e| SdwanError::FlexiWanError(e.to_string()))?;
        
        let mut token = self.token.write().await;
        *token = Some(auth_response.token);
        
        // Get organizations and set first one
        if let Some(org) = auth_response.organizations.first() {
            let mut org_id = self.org_id.write().await;
            *org_id = Some(org.id.clone());
        }
        
        info!("Authenticated with FlexiWAN");
        Ok(())
    }
    
    /// Make authenticated GET request
    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let token = self.token.read().await;
        let token_str = token.as_ref()
            .ok_or_else(|| SdwanError::FlexiWanError("Not authenticated".to_string()))?;
        
        let url = format!("{}{}", self.base_url, path);
        debug!("GET {}", url);
        
        let response = self.client
            .get(&url)
            .bearer_auth(token_str)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(SdwanError::FlexiWanError(format!("{}: {}", status, text)));
        }
        
        response.json().await
            .map_err(|e| SdwanError::FlexiWanError(e.to_string()))
    }
    
    /// Make authenticated POST request
    async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let token = self.token.read().await;
        let token_str = token.as_ref()
            .ok_or_else(|| SdwanError::FlexiWanError("Not authenticated".to_string()))?;
        
        let url = format!("{}{}", self.base_url, path);
        debug!("POST {}", url);
        
        let response = self.client
            .post(&url)
            .bearer_auth(token_str)
            .json(body)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(SdwanError::FlexiWanError(format!("{}: {}", status, text)));
        }
        
        response.json().await
            .map_err(|e| SdwanError::FlexiWanError(e.to_string()))
    }
    
    /// List devices
    pub async fn list_devices(&self) -> Result<Vec<FlexiDevice>> {
        let devices: DevicesResponse = self.get("/api/devices").await?;
        Ok(devices.data)
    }
    
    /// Get device by ID
    pub async fn get_device(&self, id: &str) -> Result<FlexiDevice> {
        let device: FlexiDevice = self.get(&format!("/api/devices/{}", id)).await?;
        Ok(device)
    }
    
    /// List tunnels
    pub async fn list_tunnels(&self) -> Result<Vec<FlexiTunnel>> {
        let tunnels: TunnelsResponse = self.get("/api/tunnels").await?;
        Ok(tunnels.data)
    }
    
    /// Get device token for enrollment
    pub async fn create_device_token(&self, device_name: &str) -> Result<String> {
        let org_id = self.org_id.read().await;
        let org = org_id.as_ref()
            .ok_or_else(|| SdwanError::FlexiWanError("No organization set".to_string()))?;
        
        let response: TokenResponse = self.post(
            &format!("/api/organizations/{}/tokens", org),
            &serde_json::json!({ "deviceName": device_name }),
        ).await?;
        
        Ok(response.token)
    }
    
    /// Create segment
    pub async fn create_segment(&self, segment: &FlexiSegment) -> Result<FlexiSegment> {
        let org_id = self.org_id.read().await;
        let org = org_id.as_ref()
            .ok_or_else(|| SdwanError::FlexiWanError("No organization set".to_string()))?;
        
        self.post(&format!("/api/organizations/{}/segments", org), segment).await
    }
    
    /// List segments
    pub async fn list_segments(&self) -> Result<Vec<FlexiSegment>> {
        let org_id = self.org_id.read().await;
        let org = org_id.as_ref()
            .ok_or_else(|| SdwanError::FlexiWanError("No organization set".to_string()))?;
        
        let segments: SegmentsResponse = self.get(&format!("/api/organizations/{}/segments", org)).await?;
        Ok(segments.data)
    }
    
    /// Create routing policy
    pub async fn create_policy(&self, policy: &FlexiPolicy) -> Result<FlexiPolicy> {
        let org_id = self.org_id.read().await;
        let org = org_id.as_ref()
            .ok_or_else(|| SdwanError::FlexiWanError("No organization set".to_string()))?;
        
        self.post(&format!("/api/organizations/{}/policies", org), policy).await
    }
    
    /// List policies
    pub async fn list_policies(&self) -> Result<Vec<FlexiPolicy>> {
        let org_id = self.org_id.read().await;
        let org = org_id.as_ref()
            .ok_or_else(|| SdwanError::FlexiWanError("No organization set".to_string()))?;
        
        let policies: PoliciesResponse = self.get(&format!("/api/organizations/{}/policies", org)).await?;
        Ok(policies.data)
    }
    
    /// Get device statistics
    pub async fn get_device_stats(&self, device_id: &str) -> Result<FlexiDeviceStats> {
        self.get(&format!("/api/devices/{}/statistics", device_id)).await
    }
    
    /// Get tunnel statistics
    pub async fn get_tunnel_stats(&self, tunnel_id: &str) -> Result<FlexiTunnelStats> {
        self.get(&format!("/api/tunnels/{}/statistics", tunnel_id)).await
    }
    
    /// Check API health
    pub async fn health_check(&self) -> Result<bool> {
        let response = self.client
            .get(&format!("{}/api/health", self.base_url))
            .send()
            .await?;
        
        Ok(response.status().is_success())
    }
}

// API Response types

#[derive(Debug, Deserialize)]
struct AuthResponse {
    token: String,
    #[serde(default)]
    organizations: Vec<Organization>,
}

#[derive(Debug, Deserialize)]
struct Organization {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct DevicesResponse {
    data: Vec<FlexiDevice>,
}

#[derive(Debug, Deserialize)]
struct TunnelsResponse {
    data: Vec<FlexiTunnel>,
}

#[derive(Debug, Deserialize)]
struct SegmentsResponse {
    data: Vec<FlexiSegment>,
}

#[derive(Debug, Deserialize)]
struct PoliciesResponse {
    data: Vec<FlexiPolicy>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

// Import models
use super::models::{FlexiDevice, FlexiTunnel, FlexiSegment, FlexiPolicy, FlexiDeviceStats, FlexiTunnelStats};
