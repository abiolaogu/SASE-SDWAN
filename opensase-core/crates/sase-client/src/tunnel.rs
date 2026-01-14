//! WireGuard Tunnel Manager
//!
//! Cross-platform WireGuard tunnel management.

use std::net::SocketAddr;
use std::sync::Arc;

pub struct TunnelManager {
    state: parking_lot::RwLock<TunnelState>,
    config: parking_lot::RwLock<Option<TunnelConfig>>,
    stats: parking_lot::RwLock<TunnelStats>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TunnelConfig {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub last_handshake: Option<chrono::DateTime<chrono::Utc>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            state: parking_lot::RwLock::new(TunnelState::Disconnected),
            config: parking_lot::RwLock::new(None),
            stats: parking_lot::RwLock::new(TunnelStats::default()),
        }
    }
    
    pub async fn connect(&self, config: TunnelConfig) -> Result<(), TunnelError> {
        *self.state.write() = TunnelState::Connecting;
        
        tracing::info!("Connecting to {}", config.server_endpoint);
        
        // Platform-specific tunnel creation
        #[cfg(target_os = "windows")]
        self.connect_windows(&config).await?;
        
        #[cfg(target_os = "macos")]
        self.connect_macos(&config).await?;
        
        #[cfg(target_os = "linux")]
        self.connect_linux(&config).await?;
        
        #[cfg(any(target_os = "ios", target_os = "android"))]
        self.connect_mobile(&config).await?;
        
        *self.config.write() = Some(config);
        *self.state.write() = TunnelState::Connected;
        
        // Start stats collection
        self.start_stats_collection();
        
        Ok(())
    }
    
    pub async fn disconnect(&self) -> Result<(), TunnelError> {
        tracing::info!("Disconnecting tunnel");
        
        #[cfg(target_os = "windows")]
        self.disconnect_windows().await?;
        
        #[cfg(target_os = "macos")]
        self.disconnect_macos().await?;
        
        #[cfg(target_os = "linux")]
        self.disconnect_linux().await?;
        
        #[cfg(any(target_os = "ios", target_os = "android"))]
        self.disconnect_mobile().await?;
        
        *self.state.write() = TunnelState::Disconnected;
        *self.config.write() = None;
        
        Ok(())
    }
    
    pub fn state(&self) -> TunnelState {
        *self.state.read()
    }
    
    pub fn stats(&self) -> TunnelStats {
        self.stats.read().clone()
    }
    
    // Windows implementation
    #[cfg(target_os = "windows")]
    async fn connect_windows(&self, config: &TunnelConfig) -> Result<(), TunnelError> {
        // Use WireGuard-NT or wireguard-windows service
        tracing::info!("Configuring WireGuard on Windows");
        
        // Create TUN adapter via wintun
        // Configure WireGuard interface
        // Add routes
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    async fn disconnect_windows(&self) -> Result<(), TunnelError> {
        Ok(())
    }
    
    // macOS implementation
    #[cfg(target_os = "macos")]
    async fn connect_macos(&self, config: &TunnelConfig) -> Result<(), TunnelError> {
        // Use Network Extension or wireguard-go
        tracing::info!("Configuring WireGuard on macOS");
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    async fn disconnect_macos(&self) -> Result<(), TunnelError> {
        Ok(())
    }
    
    // Linux implementation
    #[cfg(target_os = "linux")]
    async fn connect_linux(&self, config: &TunnelConfig) -> Result<(), TunnelError> {
        // Use kernel WireGuard or wireguard-go
        tracing::info!("Configuring WireGuard on Linux");
        
        // Create wg interface
        // Configure with wg set
        // Add routes with ip route
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    async fn disconnect_linux(&self) -> Result<(), TunnelError> {
        Ok(())
    }
    
    // Mobile implementation
    #[cfg(any(target_os = "ios", target_os = "android"))]
    async fn connect_mobile(&self, config: &TunnelConfig) -> Result<(), TunnelError> {
        // Use boringtun userspace implementation
        tracing::info!("Configuring WireGuard on mobile");
        Ok(())
    }
    
    #[cfg(any(target_os = "ios", target_os = "android"))]
    async fn disconnect_mobile(&self) -> Result<(), TunnelError> {
        Ok(())
    }
    
    fn start_stats_collection(&self) {
        // Stats collection runs in background
    }
}

impl Default for TunnelManager {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("Failed to create interface: {0}")]
    InterfaceError(String),
    
    #[error("Failed to configure: {0}")]
    ConfigError(String),
    
    #[error("Handshake failed: {0}")]
    HandshakeError(String),
    
    #[error("Connection lost: {0}")]
    ConnectionLost(String),
}
