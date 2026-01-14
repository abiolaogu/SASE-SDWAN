//! OpenSASE Edge - Site Edge Appliance
//!
//! Deployable edge appliance for branch offices.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         OPENSASE EDGE APPLIANCE                         │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                        WAN INTERFACES                            │   │
//! │  │   WAN1 (Primary)    WAN2 (Backup)    LTE (Failover)             │   │
//! │  └─────────┬───────────────┬────────────────┬───────────────────────┘   │
//! │            │               │                │                           │
//! │  ┌─────────▼───────────────▼────────────────▼───────────────────────┐   │
//! │  │                    SD-WAN CONTROLLER                              │   │
//! │  │   Path Selection | Traffic Steering | Link Bonding | Failover    │   │
//! │  └─────────────────────────────┬─────────────────────────────────────┘   │
//! │                                │                                        │
//! │  ┌─────────────────────────────▼─────────────────────────────────────┐   │
//! │  │                    SECURITY STACK                                 │   │
//! │  │   Firewall | IPS | URL Filter | App Control | DNS Security       │   │
//! │  └─────────────────────────────┬─────────────────────────────────────┘   │
//! │                                │                                        │
//! │  ┌─────────────────────────────▼─────────────────────────────────────┐   │
//! │  │                        LAN INTERFACE                              │   │
//! │  │                    Branch Network (10.0.0.0/24)                   │   │
//! │  └───────────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod config;
pub mod network;
pub mod sdwan;
pub mod security;
pub mod tunnel;
pub mod api;
pub mod health;
pub mod routing;
pub mod ha;
pub mod ztp;
pub mod services;
pub mod metrics;
pub mod hardware;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;

pub use config::EdgeConfig;
pub use network::{Interface, InterfaceManager};
pub use sdwan::SdwanController;
pub use security::SecurityStack;
pub use tunnel::TunnelManager;

/// Edge error types
#[derive(Debug, Error)]
pub enum EdgeError {
    #[error("network error: {0}")]
    Network(String),
    #[error("tunnel error: {0}")]
    Tunnel(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("security error: {0}")]
    Security(String),
}

/// Main Edge Appliance
pub struct OpenSASEEdge {
    /// Configuration
    pub config: Arc<RwLock<EdgeConfig>>,
    /// Interface manager
    pub interfaces: Arc<InterfaceManager>,
    /// SD-WAN controller
    pub sdwan: Arc<SdwanController>,
    /// Security stack
    pub security: Arc<SecurityStack>,
    /// Tunnel manager
    pub tunnels: Arc<TunnelManager>,
    /// State
    state: Arc<RwLock<EdgeState>>,
}

impl OpenSASEEdge {
    /// Create new edge appliance
    pub fn new(config: EdgeConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            interfaces: Arc::new(InterfaceManager::new()),
            sdwan: Arc::new(SdwanController::new()),
            security: Arc::new(SecurityStack::new()),
            tunnels: Arc::new(TunnelManager::new()),
            state: Arc::new(RwLock::new(EdgeState::Initializing)),
        }
    }

    /// Initialize appliance
    pub async fn init(&self) -> Result<(), EdgeError> {
        tracing::info!("Initializing OpenSASE Edge...");
        
        let config = self.config.read();
        
        // 1. Configure interfaces
        self.interfaces.configure(&config.interfaces).await?;
        
        // 2. Register with controller
        self.register_with_controller().await?;
        
        // 3. Establish tunnels to PoPs
        self.tunnels.connect_all(&config.pop_connections).await?;
        
        // 4. Initialize security stack
        self.security.init().await?;
        
        // 5. Start SD-WAN
        self.sdwan.start().await?;
        
        *self.state.write() = EdgeState::Running;
        tracing::info!("OpenSASE Edge initialized");
        
        Ok(())
    }

    /// Run main loop
    pub async fn run(&self) -> Result<(), EdgeError> {
        let api_handle = self.start_api_server();
        let health_handle = self.start_health_monitor();
        
        tokio::select! {
            _ = api_handle => {},
            _ = health_handle => {},
        }
        
        Ok(())
    }

    async fn register_with_controller(&self) -> Result<(), EdgeError> {
        tracing::info!("Registering with controller...");
        // In production: HTTPS to controller
        Ok(())
    }

    async fn start_api_server(&self) -> Result<(), EdgeError> {
        api::start_server(self.config.clone()).await
    }

    async fn start_health_monitor(&self) -> Result<(), EdgeError> {
        health::start_monitor(
            self.interfaces.clone(),
            self.tunnels.clone(),
        ).await
    }

    /// Get current state
    pub fn state(&self) -> EdgeState {
        *self.state.read()
    }
}

/// Edge state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeState {
    Initializing,
    Running,
    Degraded,
    Error,
    Shutdown,
}
