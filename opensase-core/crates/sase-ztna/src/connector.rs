//! Application Connector
//!
//! Secure tunnels to protected applications.

use crate::{Session, Resource, Identity};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Application connector manager
pub struct ConnectorManager {
    /// Registered connectors
    connectors: dashmap::DashMap<String, ApplicationConnector>,
    /// Active tunnels
    tunnels: dashmap::DashMap<String, MicroTunnel>,
    /// Session bindings
    session_bindings: dashmap::DashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ApplicationConnector {
    pub id: String,
    pub name: String,
    pub application_id: String,
    pub connector_type: ConnectorType,
    pub endpoint: SocketAddr,
    pub health: ConnectorHealth,
    pub capabilities: ConnectorCapabilities,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorType {
    /// Agent installed on-premises
    Agent,
    /// Cloud-native connector
    CloudNative,
    /// ZTNA tunnel
    Tunnel,
    /// Reverse proxy
    Proxy,
    /// Clientless browser
    Clientless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ConnectorCapabilities {
    pub supports_tcp: bool,
    pub supports_udp: bool,
    pub supports_http: bool,
    pub supports_rdp: bool,
    pub supports_ssh: bool,
    pub max_concurrent_sessions: u32,
    pub dlp_enabled: bool,
    pub session_recording: bool,
}

impl Default for ConnectorCapabilities {
    fn default() -> Self {
        Self {
            supports_tcp: true,
            supports_udp: false,
            supports_http: true,
            supports_rdp: true,
            supports_ssh: true,
            max_concurrent_sessions: 1000,
            dlp_enabled: true,
            session_recording: true,
        }
    }
}

/// Micro-tunnel for secure application access
#[derive(Debug, Clone)]
pub struct MicroTunnel {
    pub id: String,
    pub session_id: String,
    pub connector_id: String,
    pub application_id: String,
    pub user_id: String,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: TunnelProtocol,
    pub state: TunnelState,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub encryption: TunnelEncryption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelProtocol {
    Tcp,
    Udp,
    Http,
    Https,
    Ssh,
    Rdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Establishing,
    Active,
    Suspended,
    Closed,
}

#[derive(Debug, Clone)]
pub struct TunnelEncryption {
    pub cipher: String,
    pub key_exchange: String,
    pub certificate_verified: bool,
}

impl ConnectorManager {
    pub fn new() -> Self {
        Self {
            connectors: dashmap::DashMap::new(),
            tunnels: dashmap::DashMap::new(),
            session_bindings: dashmap::DashMap::new(),
        }
    }
    
    /// Register application connector
    pub fn register_connector(&self, connector: ApplicationConnector) {
        tracing::info!(
            "Registering connector {} for application {}",
            connector.id, connector.application_id
        );
        self.connectors.insert(connector.id.clone(), connector);
    }
    
    /// Get connectors for application
    pub fn get_connectors(&self, application_id: &str) -> Vec<ApplicationConnector> {
        self.connectors.iter()
            .filter(|c| c.application_id == application_id)
            .filter(|c| c.health == ConnectorHealth::Healthy)
            .map(|c| c.clone())
            .collect()
    }
    
    /// Create micro-tunnel
    pub async fn create_tunnel(
        &self,
        session: &Session,
        resource: &Resource,
        protocol: TunnelProtocol,
    ) -> Result<MicroTunnel, ConnectorError> {
        // Find suitable connector
        let connectors = self.get_connectors(&resource.id);
        let connector = connectors.first()
            .ok_or(ConnectorError::NoConnectorAvailable)?;
        
        // Create tunnel
        let tunnel = MicroTunnel {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            connector_id: connector.id.clone(),
            application_id: resource.id.clone(),
            user_id: session.identity.user_id.clone(),
            source: "0.0.0.0:0".parse().unwrap(),
            destination: connector.endpoint,
            protocol,
            state: TunnelState::Establishing,
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            bytes_sent: 0,
            bytes_received: 0,
            encryption: TunnelEncryption {
                cipher: "AES-256-GCM".to_string(),
                key_exchange: "ECDHE".to_string(),
                certificate_verified: true,
            },
        };
        
        // Store tunnel
        self.tunnels.insert(tunnel.id.clone(), tunnel.clone());
        
        // Bind to session
        self.session_bindings.entry(session.id.clone())
            .or_insert_with(Vec::new)
            .push(tunnel.id.clone());
        
        tracing::info!(
            "Created tunnel {} for session {} to {}",
            tunnel.id, session.id, resource.name
        );
        
        Ok(tunnel)
    }
    
    /// Activate tunnel
    pub async fn activate_tunnel(&self, tunnel_id: &str) -> Result<(), ConnectorError> {
        if let Some(mut tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.state = TunnelState::Active;
            tunnel.last_activity = chrono::Utc::now();
            Ok(())
        } else {
            Err(ConnectorError::TunnelNotFound)
        }
    }
    
    /// Close tunnel
    pub async fn close_tunnel(&self, tunnel_id: &str) {
        if let Some(mut tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.state = TunnelState::Closed;
        }
    }
    
    /// Close all tunnels for session
    pub async fn close_session_tunnels(&self, session_id: &str) {
        if let Some(tunnel_ids) = self.session_bindings.remove(session_id) {
            for tunnel_id in tunnel_ids.1 {
                self.close_tunnel(&tunnel_id).await;
            }
        }
    }
    
    /// Get active tunnels for session
    pub fn get_session_tunnels(&self, session_id: &str) -> Vec<MicroTunnel> {
        self.session_bindings.get(session_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.tunnels.get(id))
                    .map(|t| t.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Update tunnel activity
    pub fn update_activity(&self, tunnel_id: &str, bytes_sent: u64, bytes_received: u64) {
        if let Some(mut tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.last_activity = chrono::Utc::now();
            tunnel.bytes_sent += bytes_sent;
            tunnel.bytes_received += bytes_received;
        }
    }
    
    /// Get tunnel stats
    pub fn get_stats(&self) -> ConnectorStats {
        let mut stats = ConnectorStats::default();
        
        stats.total_connectors = self.connectors.len();
        stats.healthy_connectors = self.connectors.iter()
            .filter(|c| c.health == ConnectorHealth::Healthy)
            .count();
        
        for tunnel in self.tunnels.iter() {
            stats.total_tunnels += 1;
            match tunnel.state {
                TunnelState::Active => stats.active_tunnels += 1,
                TunnelState::Establishing => stats.establishing_tunnels += 1,
                _ => {}
            }
            stats.total_bytes_sent += tunnel.bytes_sent;
            stats.total_bytes_received += tunnel.bytes_received;
        }
        
        stats
    }
}

impl Default for ConnectorManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct ConnectorStats {
    pub total_connectors: usize,
    pub healthy_connectors: usize,
    pub total_tunnels: usize,
    pub active_tunnels: usize,
    pub establishing_tunnels: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

#[derive(Debug)]
pub enum ConnectorError {
    NoConnectorAvailable,
    TunnelNotFound,
    ConnectionFailed,
    ProtocolNotSupported,
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoConnectorAvailable => write!(f, "No connector available"),
            Self::TunnelNotFound => write!(f, "Tunnel not found"),
            Self::ConnectionFailed => write!(f, "Connection failed"),
            Self::ProtocolNotSupported => write!(f, "Protocol not supported"),
        }
    }
}

impl std::error::Error for ConnectorError {}
