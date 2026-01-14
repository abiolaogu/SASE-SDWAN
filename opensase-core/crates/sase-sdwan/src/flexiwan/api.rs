//! FlexiWAN API Client
//!
//! Complete API wrapper for flexiManage orchestration.

use crate::{Result, SdwanError};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn, debug};

/// FlexiWAN API Client
pub struct FlexiWanApi {
    client: Client,
    base_url: String,
    api_token: String,
}

impl FlexiWanApi {
    /// Create new API client
    pub fn new(base_url: &str, api_token: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: api_token.to_string(),
        }
    }
    
    /// Login and get API token
    pub async fn login(base_url: &str, email: &str, password: &str) -> Result<Self> {
        let client = Client::new();
        
        let resp = client
            .post(&format!("{}/api/users/login", base_url))
            .json(&serde_json::json!({
                "email": email,
                "password": password
            }))
            .send()
            .await?;
        
        if !resp.status().is_success() {
            return Err(SdwanError::FlexiWanError("Login failed".to_string()));
        }
        
        let login_resp: LoginResponse = resp.json().await
            .map_err(|e| SdwanError::FlexiWanError(e.to_string()))?;
        
        Ok(Self::new(base_url, &login_resp.token))
    }
    
    // ==========================================
    // Organizations
    // ==========================================
    
    /// Create a new organization
    pub async fn create_organization(&self, name: &str) -> Result<Organization> {
        let resp = self.client
            .post(&format!("{}/api/organizations", self.base_url))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Get organization by ID
    pub async fn get_organization(&self, org_id: &str) -> Result<Organization> {
        let resp = self.client
            .get(&format!("{}/api/organizations/{}", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// List all organizations
    pub async fn list_organizations(&self) -> Result<Vec<Organization>> {
        let resp = self.client
            .get(&format!("{}/api/organizations", self.base_url))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    // ==========================================
    // Devices
    // ==========================================
    
    /// Register a new device
    pub async fn register_device(&self, org_id: &str, device: DeviceRegistration) -> Result<Device> {
        let resp = self.client
            .post(&format!("{}/api/organizations/{}/devices", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .json(&device)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Get device by ID
    pub async fn get_device(&self, device_id: &str) -> Result<Device> {
        let resp = self.client
            .get(&format!("{}/api/devices/{}", self.base_url, device_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// List devices in organization
    pub async fn list_devices(&self, org_id: &str) -> Result<Vec<Device>> {
        let resp = self.client
            .get(&format!("{}/api/organizations/{}/devices", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Get device status
    pub async fn get_device_status(&self, device_id: &str) -> Result<DeviceStatus> {
        let resp = self.client
            .get(&format!("{}/api/devices/{}/status", self.base_url, device_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Approve device
    pub async fn approve_device(&self, device_id: &str) -> Result<Device> {
        let resp = self.client
            .post(&format!("{}/api/devices/{}/approve", self.base_url, device_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Start device
    pub async fn start_device(&self, device_id: &str) -> Result<()> {
        let resp = self.client
            .post(&format!("{}/api/devices/{}/start", self.base_url, device_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_empty_response(resp).await
    }
    
    /// Stop device
    pub async fn stop_device(&self, device_id: &str) -> Result<()> {
        let resp = self.client
            .post(&format!("{}/api/devices/{}/stop", self.base_url, device_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_empty_response(resp).await
    }
    
    // ==========================================
    // Tunnels
    // ==========================================
    
    /// Create tunnel between two devices
    pub async fn create_tunnel(&self, org_id: &str, tunnel: TunnelDefinition) -> Result<Tunnel> {
        let resp = self.client
            .post(&format!("{}/api/organizations/{}/tunnels", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .json(&tunnel)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Get tunnel by ID
    pub async fn get_tunnel(&self, tunnel_id: &str) -> Result<Tunnel> {
        let resp = self.client
            .get(&format!("{}/api/tunnels/{}", self.base_url, tunnel_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// List tunnels in organization
    pub async fn list_tunnels(&self, org_id: &str) -> Result<Vec<Tunnel>> {
        let resp = self.client
            .get(&format!("{}/api/organizations/{}/tunnels", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Delete tunnel
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<()> {
        let resp = self.client
            .delete(&format!("{}/api/tunnels/{}", self.base_url, tunnel_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_empty_response(resp).await
    }
    
    // ==========================================
    // Policies
    // ==========================================
    
    /// Apply routing policy
    pub async fn apply_routing_policy(&self, org_id: &str, policy: RoutingPolicy) -> Result<Policy> {
        let resp = self.client
            .post(&format!("{}/api/organizations/{}/policies/routing", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .json(&policy)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Apply firewall policy
    pub async fn apply_firewall_policy(&self, org_id: &str, policy: FirewallPolicy) -> Result<Policy> {
        let resp = self.client
            .post(&format!("{}/api/organizations/{}/policies/firewall", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .json(&policy)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Apply QoS policy
    pub async fn apply_qos_policy(&self, org_id: &str, policy: QosPolicy) -> Result<Policy> {
        let resp = self.client
            .post(&format!("{}/api/organizations/{}/policies/qos", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .json(&policy)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// List policies
    pub async fn list_policies(&self, org_id: &str) -> Result<Vec<Policy>> {
        let resp = self.client
            .get(&format!("{}/api/organizations/{}/policies", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    // ==========================================
    // Applications
    // ==========================================
    
    /// Get application definitions
    pub async fn list_applications(&self, org_id: &str) -> Result<Vec<Application>> {
        let resp = self.client
            .get(&format!("{}/api/organizations/{}/applications", self.base_url, org_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    // ==========================================
    // Statistics
    // ==========================================
    
    /// Get device statistics
    pub async fn get_device_stats(&self, device_id: &str, period: &str) -> Result<DeviceStats> {
        let resp = self.client
            .get(&format!("{}/api/devices/{}/statistics?period={}", self.base_url, device_id, period))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    /// Get tunnel statistics
    pub async fn get_tunnel_stats(&self, tunnel_id: &str) -> Result<TunnelStats> {
        let resp = self.client
            .get(&format!("{}/api/tunnels/{}/statistics", self.base_url, tunnel_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        
        self.handle_response(resp).await
    }
    
    // ==========================================
    // Helpers
    // ==========================================
    
    async fn handle_response<T: for<'de> Deserialize<'de>>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SdwanError::FlexiWanError(format!("{}: {}", status, text)));
        }
        
        resp.json().await
            .map_err(|e| SdwanError::FlexiWanError(e.to_string()))
    }
    
    async fn handle_empty_response(&self, resp: reqwest::Response) -> Result<()> {
        let status = resp.status();
        
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SdwanError::FlexiWanError(format!("{}: {}", status, text)));
        }
        
        Ok(())
    }
}

// ==========================================
// API Types
// ==========================================

#[derive(Debug, Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub name: String,
    pub description: Option<String>,
    pub site: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub hostname: Option<String>,
    pub is_approved: bool,
    pub is_connected: bool,
    pub is_running: bool,
    pub interfaces: Vec<Interface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub is_assigned: bool,
    pub interface_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub device_id: String,
    pub state: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub uptime: u64,
    pub last_connection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelDefinition {
    pub device_a: String,
    pub device_b: String,
    pub interface_a: String,
    pub interface_b: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub device_a: String,
    pub device_b: String,
    pub is_active: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<RoutingRule>,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    pub application: String,
    pub priority: u32,
    pub action: String,
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPolicy {
    pub name: String,
    pub rules: Vec<FirewallRule>,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub action: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosPolicy {
    pub name: String,
    pub bandwidth_limit: Option<u64>,
    pub priority: u32,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStats {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub loss_percent: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
