//! OpenSASE Client Suite (OSCS)
//!
//! Cross-platform ZTNA client providing:
//! - Secure WireGuard tunneling
//! - Device posture collection
//! - Always-on protection
//! - Split tunneling
//!
//! # Platform Support
//! - Windows 10/11 (x64, ARM64)
//! - macOS 12+ (Intel, Apple Silicon)
//! - Linux (Ubuntu, Fedora, Debian)
//! - iOS 15+
//! - Android 10+
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      OpenSASE Client                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
//! │  │   Tunnel    │  │   Posture   │  │   Policy    │             │
//! │  │  Manager    │  │  Collector  │  │   Engine    │             │
//! │  └─────────────┘  └─────────────┘  └─────────────┘             │
//! │                         │                                        │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              Platform Abstraction Layer                  │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │         │              │              │              │          │
//! │    ┌────┴───┐    ┌────┴───┐    ┌────┴───┐    ┌────┴───┐      │
//! │    │Windows │    │ macOS  │    │ Linux  │    │ Mobile │      │
//! │    └────────┘    └────────┘    └────────┘    └────────┘      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// Module declarations
pub mod tunnel;
pub mod posture;
pub mod policy;
pub mod connection;
pub mod platform;
pub mod config;
pub mod auth;
pub mod dns;

#[cfg(feature = "ffi")]
pub mod ffi;

// =============================================================================
// Core Types
// =============================================================================

/// Client configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server endpoint
    pub server_url: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Device ID (persistent)
    pub device_id: String,
    /// Client version
    pub version: String,
    /// Features
    pub features: ClientFeatures,
    /// Connection settings
    pub connection: ConnectionSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientFeatures {
    pub always_on: bool,
    pub split_tunnel: bool,
    pub dns_protection: bool,
    pub posture_check: bool,
    pub auto_reconnect: bool,
}

impl Default for ClientFeatures {
    fn default() -> Self {
        Self {
            always_on: true,
            split_tunnel: true,
            dns_protection: true,
            posture_check: true,
            auto_reconnect: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionSettings {
    pub reconnect_delay_ms: u64,
    pub max_reconnect_attempts: u32,
    pub keepalive_interval_secs: u64,
    pub mtu: u16,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            reconnect_delay_ms: 1000,
            max_reconnect_attempts: 10,
            keepalive_interval_secs: 25,
            mtu: 1420,
        }
    }
}

/// Client state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientState {
    Disconnected,
    Connecting,
    Authenticating,
    PostureCheck,
    Connected,
    Reconnecting,
    Error,
}

/// Connection status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub state: ClientState,
    pub connected_at: Option<DateTime<Utc>>,
    pub server_ip: Option<String>,
    pub client_ip: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_ms: Option<u32>,
    pub last_handshake: Option<DateTime<Utc>>,
}

impl Default for ConnectionStatus {
    fn default() -> Self {
        Self {
            state: ClientState::Disconnected,
            connected_at: None,
            server_ip: None,
            client_ip: None,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
            last_handshake: None,
        }
    }
}

// =============================================================================
// Main Client
// =============================================================================

/// OpenSASE Client
pub struct SaseClient {
    config: ClientConfig,
    state: parking_lot::RwLock<ClientState>,
    status: parking_lot::RwLock<ConnectionStatus>,
    tunnel: tunnel::TunnelManager,
    posture: posture::PostureCollector,
    policy: policy::PolicyEngine,
    auth: auth::AuthManager,
    dns: dns::DnsManager,
    event_tx: tokio::sync::broadcast::Sender<ClientEvent>,
}

/// Client events for UI binding
#[derive(Clone, Debug, Serialize)]
pub enum ClientEvent {
    StateChanged(ClientState),
    Connected { server: String, client_ip: String },
    Disconnected { reason: String },
    PostureChanged(posture::PostureResult),
    PolicyUpdated,
    Error { code: String, message: String },
    Stats { bytes_sent: u64, bytes_received: u64 },
}

impl SaseClient {
    /// Create new client instance
    pub fn new(config: ClientConfig) -> Self {
        let (event_tx, _) = tokio::sync::broadcast::channel(100);
        
        Self {
            config: config.clone(),
            state: parking_lot::RwLock::new(ClientState::Disconnected),
            status: parking_lot::RwLock::new(ConnectionStatus::default()),
            tunnel: tunnel::TunnelManager::new(),
            posture: posture::PostureCollector::new(),
            policy: policy::PolicyEngine::new(),
            auth: auth::AuthManager::new(&config.server_url, &config.tenant_id),
            dns: dns::DnsManager::new(),
            event_tx,
        }
    }
    
    /// Connect to SASE network
    pub async fn connect(&self) -> Result<(), ClientError> {
        self.set_state(ClientState::Connecting);
        
        // Step 1: Authenticate
        self.set_state(ClientState::Authenticating);
        let auth_result = self.auth.authenticate().await
            .map_err(|e| ClientError::AuthFailed(e.to_string()))?;
        
        // Step 2: Collect posture
        self.set_state(ClientState::PostureCheck);
        let posture_result = self.posture.collect().await;
        self.emit_event(ClientEvent::PostureChanged(posture_result.clone()));
        
        // Step 3: Get tunnel config from server
        let tunnel_config = self.auth.get_tunnel_config(&auth_result.token).await
            .map_err(|e| ClientError::ConfigFailed(e.to_string()))?;
        
        // Step 4: Establish tunnel
        self.tunnel.connect(tunnel_config).await
            .map_err(|e| ClientError::TunnelFailed(e.to_string()))?;
        
        // Step 5: Configure DNS
        if self.config.features.dns_protection {
            self.dns.configure(&tunnel_config.dns_servers).await?;
        }
        
        // Step 6: Apply policies
        self.policy.apply(&tunnel_config.policies).await?;
        
        // Update status
        {
            let mut status = self.status.write();
            status.state = ClientState::Connected;
            status.connected_at = Some(Utc::now());
            status.server_ip = Some(tunnel_config.server_endpoint.clone());
            status.client_ip = Some(tunnel_config.client_ip.clone());
        }
        
        self.set_state(ClientState::Connected);
        self.emit_event(ClientEvent::Connected {
            server: tunnel_config.server_endpoint,
            client_ip: tunnel_config.client_ip,
        });
        
        // Start keepalive task
        self.start_keepalive();
        
        Ok(())
    }
    
    /// Disconnect from SASE network
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        // Restore DNS
        self.dns.restore().await?;
        
        // Close tunnel
        self.tunnel.disconnect().await?;
        
        // Update state
        self.set_state(ClientState::Disconnected);
        {
            let mut status = self.status.write();
            status.state = ClientState::Disconnected;
            status.connected_at = None;
        }
        
        self.emit_event(ClientEvent::Disconnected {
            reason: "User initiated".to_string(),
        });
        
        Ok(())
    }
    
    /// Get current connection status
    pub fn status(&self) -> ConnectionStatus {
        self.status.read().clone()
    }
    
    /// Get current state
    pub fn state(&self) -> ClientState {
        *self.state.read()
    }
    
    /// Subscribe to events
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ClientEvent> {
        self.event_tx.subscribe()
    }
    
    /// Force posture re-check
    pub async fn refresh_posture(&self) -> posture::PostureResult {
        let result = self.posture.collect().await;
        self.emit_event(ClientEvent::PostureChanged(result.clone()));
        result
    }
    
    fn set_state(&self, state: ClientState) {
        *self.state.write() = state;
        self.emit_event(ClientEvent::StateChanged(state));
    }
    
    fn emit_event(&self, event: ClientEvent) {
        let _ = self.event_tx.send(event);
    }
    
    fn start_keepalive(&self) {
        // Keepalive is handled by tunnel manager
    }
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Configuration failed: {0}")]
    ConfigFailed(String),
    
    #[error("Tunnel failed: {0}")]
    TunnelFailed(String),
    
    #[error("DNS configuration failed: {0}")]
    DnsFailed(String),
    
    #[error("Policy error: {0}")]
    PolicyError(String),
    
    #[error("Platform error: {0}")]
    PlatformError(String),
}

// =============================================================================
// Platform Detection
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub device_type: DeviceType,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceType {
    Desktop,
    Laptop,
    Mobile,
    Tablet,
    Server,
    Unknown,
}

impl PlatformInfo {
    pub fn detect() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            os_version: Self::get_os_version(),
            arch: std::env::consts::ARCH.to_string(),
            device_type: Self::detect_device_type(),
        }
    }
    
    fn get_os_version() -> String {
        #[cfg(target_os = "windows")]
        {
            "10.0".to_string() // Simplified
        }
        #[cfg(target_os = "macos")]
        {
            "14.0".to_string() // Simplified
        }
        #[cfg(target_os = "linux")]
        {
            "6.0".to_string() // Simplified
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            "unknown".to_string()
        }
    }
    
    fn detect_device_type() -> DeviceType {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            DeviceType::Mobile
        }
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            DeviceType::Desktop
        }
    }
}
