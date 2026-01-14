//! OpenSASE Client - Cross-Platform Edge Client
//!
//! Enterprise-grade SASE client rivaling Zscaler Client Connector and Cato Client.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         OPENSASE CLIENT (OSC)                           │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │   Tunnel     │  │   Traffic    │  │   Posture    │  │   Policy    │ │
//! │  │   Manager    │  │ Interceptor  │  │  Assessor    │  │   Engine    │ │
//! │  │  (WireGuard) │  │  (WFP/iptab) │  │  (Compliance)│  │  (Cached)   │ │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
//! │         │                 │                 │                 │        │
//! │  ┌──────▼─────────────────▼─────────────────▼─────────────────▼──────┐ │
//! │  │                      Core Service Loop                            │ │
//! │  └───────────────────────────────────────────────────────────────────┘ │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
//! │  │  Telemetry   │  │   Update     │  │    Config    │                  │
//! │  │  Collector   │  │   Manager    │  │   Manager    │                  │
//! │  └──────────────┘  └──────────────┘  └──────────────┘                  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod tunnel;
pub mod traffic;
pub mod posture;
pub mod policy;
pub mod telemetry;
pub mod config;
pub mod update;
pub mod platform;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;

pub use tunnel::TunnelManager;
pub use traffic::TrafficInterceptor;
pub use posture::{PostureAssessor, DevicePosture};
pub use policy::LocalPolicyEngine;
pub use config::ClientConfig;

/// Client error types
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("tunnel error: {0}")]
    Tunnel(String),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("posture error: {0}")]
    Posture(String),
    #[error("config error: {0}")]
    Config(String),
}

/// Main OpenSASE Client
pub struct OpenSASEClient {
    /// Tunnel manager
    pub tunnel_manager: Arc<TunnelManager>,
    /// Traffic interceptor
    pub traffic_interceptor: Arc<TrafficInterceptor>,
    /// Posture assessor
    pub posture_assessor: Arc<PostureAssessor>,
    /// Local policy engine
    pub policy_engine: Arc<LocalPolicyEngine>,
    /// Configuration
    pub config: Arc<RwLock<ClientConfig>>,
    /// Connection state
    state: Arc<RwLock<ConnectionState>>,
}

impl OpenSASEClient {
    /// Create new client
    pub fn new(config: ClientConfig) -> Self {
        Self {
            tunnel_manager: Arc::new(TunnelManager::new()),
            traffic_interceptor: Arc::new(TrafficInterceptor::new()),
            posture_assessor: Arc::new(PostureAssessor::new()),
            policy_engine: Arc::new(LocalPolicyEngine::new()),
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
        }
    }

    /// Connect to SASE
    pub async fn connect(&self) -> Result<(), ClientError> {
        tracing::info!("Connecting to OpenSASE...");
        
        *self.state.write() = ConnectionState::Connecting;
        
        // 1. Assess device posture
        let posture = self.posture_assessor.assess().await?;
        tracing::info!("Device posture: compliant={}", posture.is_compliant);
        
        // 2. Fetch policies
        self.policy_engine.refresh().await?;
        
        // 3. Establish tunnel
        let config = self.config.read();
        self.tunnel_manager.connect(&config.controller_url).await?;
        
        // 4. Enable traffic interception
        self.traffic_interceptor.enable(config.tunnel_mode).await?;
        
        *self.state.write() = ConnectionState::Connected;
        tracing::info!("Connected to OpenSASE");
        
        Ok(())
    }

    /// Disconnect from SASE
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        tracing::info!("Disconnecting from OpenSASE...");
        
        *self.state.write() = ConnectionState::Disconnecting;
        
        self.traffic_interceptor.disable().await?;
        self.tunnel_manager.disconnect().await?;
        
        *self.state.write() = ConnectionState::Disconnected;
        tracing::info!("Disconnected");
        
        Ok(())
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Run client service loop
    pub async fn run(&self) -> Result<(), ClientError> {
        // Auto-connect if configured
        if self.config.read().auto_connect {
            self.connect().await?;
        }

        // Main loop
        loop {
            tokio::select! {
                // Periodic posture check
                _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {
                    if let Err(e) = self.posture_assessor.assess().await {
                        tracing::warn!("Posture check failed: {}", e);
                    }
                }
            }
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}
