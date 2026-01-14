//! OpenSASE Cloud Connector (OSCC)
//!
//! Direct connectivity to major cloud providers via their private interconnect services.
//!
//! # Supported Providers
//!
//! - **AWS**: Direct Connect, Transit Gateway
//! - **Azure**: ExpressRoute, Virtual WAN
//! - **GCP**: Cloud Interconnect (Dedicated/Partner)
//! - **Oracle**: FastConnect
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Cloud Connector Architecture                  │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  OpenSASE PoP                                                   │
//! │  ┌────────────────────────────────────────────────────────────┐ │
//! │  │                    VPP Data Plane                           │ │
//! │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │ │
//! │  │  │  User    │ │  Cloud   │ │  Cloud   │ │  Cloud   │      │ │
//! │  │  │ Traffic  │ │   AWS    │ │  Azure   │ │   GCP    │      │ │
//! │  │  │Interface │ │Interface │ │Interface │ │Interface │      │ │
//! │  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │ │
//! │  │       │            │            │            │             │ │
//! │  │       └────────────┴────────────┴────────────┘             │ │
//! │  │                         │                                   │ │
//! │  │                  Policy-Based Routing                       │ │
//! │  └────────────────────────────────────────────────────────────┘ │
//! │                            │                                     │
//! │  ┌─────────────────────────┼─────────────────────────┐          │
//! │  │                         │                         │          │
//! │  ▼                         ▼                         ▼          │
//! │  ┌─────────┐         ┌─────────┐         ┌─────────┐           │
//! │  │  AWS    │         │  Azure  │         │   GCP   │           │
//! │  │ Direct  │         │Express- │         │  Cloud  │           │
//! │  │ Connect │         │  Route  │         │Interconn│           │
//! │  └─────────┘         └─────────┘         └─────────┘           │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod routing;

// =============================================================================
// Core Types
// =============================================================================

/// Cloud provider identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    Oracle,
    Alibaba,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aws => "AWS",
            Self::Azure => "Azure",
            Self::Gcp => "GCP",
            Self::Oracle => "Oracle",
            Self::Alibaba => "Alibaba",
        }
    }
}

/// Connection type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConnectionType {
    /// AWS Direct Connect
    DirectConnect { location: String, port_speed: String },
    /// Azure ExpressRoute
    ExpressRoute { peering_location: String, bandwidth_mbps: u32 },
    /// GCP Cloud Interconnect
    CloudInterconnect { interconnect_type: GcpInterconnectType },
    /// Oracle FastConnect
    FastConnect { location: String },
    /// VPN fallback
    VpnTunnel { gateway_ip: IpAddr },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GcpInterconnectType {
    Dedicated,
    Partner,
}

/// Connection status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Pending,
    Provisioning,
    Active,
    Degraded,
    Down,
    Deleting,
    Deleted,
}

/// BGP configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BgpConfig {
    pub our_asn: u32,
    pub cloud_asn: u32,
    pub our_ip: IpAddr,
    pub cloud_ip: IpAddr,
    pub md5_auth: Option<String>,
    pub advertised_prefixes: Vec<IpNet>,
    pub received_prefixes: Vec<IpNet>,
    pub local_preference: u32,
    pub med: u32,
}

/// Cloud connection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloudConnection {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub cloud_provider: CloudProvider,
    pub connection_type: ConnectionType,
    pub status: ConnectionStatus,
    pub bandwidth_mbps: u32,
    pub pop_location: String,
    pub cloud_region: String,
    pub bgp_config: BgpConfig,
    pub vlan_id: u16,
    pub routes: Vec<CloudRoute>,
    pub health: ConnectionHealth,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Cloud route
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloudRoute {
    pub prefix: IpNet,
    pub next_hop: IpAddr,
    pub connection_id: Uuid,
    pub priority: u32,
    pub weight: u32,
    pub active: bool,
}

/// Connection health metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionHealth {
    pub bgp_state: BgpState,
    pub bgp_uptime_secs: u64,
    pub prefixes_received: u32,
    pub prefixes_advertised: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub errors: u64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss: f64,
    pub last_checked: DateTime<Utc>,
}

impl Default for ConnectionHealth {
    fn default() -> Self {
        Self {
            bgp_state: BgpState::Idle,
            bgp_uptime_secs: 0,
            prefixes_received: 0,
            prefixes_advertised: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            errors: 0,
            latency_ms: 0.0,
            jitter_ms: 0.0,
            packet_loss: 0.0,
            last_checked: Utc::now(),
        }
    }
}

/// BGP session state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

// =============================================================================
// Cloud Connector Service
// =============================================================================

/// Multi-cloud connector management service
pub struct CloudConnectorService {
    connections: dashmap::DashMap<Uuid, CloudConnection>,
    route_manager: routing::CloudRouteManager,
}

impl CloudConnectorService {
    /// Create new cloud connector service
    pub fn new() -> Self {
        Self {
            connections: dashmap::DashMap::new(),
            route_manager: routing::CloudRouteManager::new(),
        }
    }
    
    /// Create new cloud connection
    pub async fn create_connection(
        &self,
        tenant_id: Uuid,
        request: CreateConnectionRequest,
    ) -> Result<CloudConnection, ConnectorError> {
        // Validate request
        self.validate_request(&request)?;
        
        // Create connection based on provider
        let connection = CloudConnection {
            id: Uuid::new_v4(),
            tenant_id,
            name: request.name,
            cloud_provider: request.cloud_provider,
            connection_type: request.connection_type,
            status: ConnectionStatus::Pending,
            bandwidth_mbps: request.bandwidth_mbps,
            pop_location: request.pop_location,
            cloud_region: request.cloud_region,
            bgp_config: request.bgp_config,
            vlan_id: request.vlan_id,
            routes: Vec::new(),
            health: ConnectionHealth::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        self.connections.insert(connection.id, connection.clone());
        
        Ok(connection)
    }
    
    /// Get connection by ID
    pub fn get_connection(&self, id: &Uuid) -> Option<CloudConnection> {
        self.connections.get(id).map(|r| r.clone())
    }
    
    /// List connections for tenant
    pub fn list_connections(&self, tenant_id: &Uuid) -> Vec<CloudConnection> {
        self.connections
            .iter()
            .filter(|r| r.tenant_id == *tenant_id)
            .map(|r| r.clone())
            .collect()
    }
    
    /// Update connection status
    pub fn update_status(&self, id: &Uuid, status: ConnectionStatus) -> Result<(), ConnectorError> {
        let mut conn = self.connections.get_mut(id)
            .ok_or(ConnectorError::ConnectionNotFound(*id))?;
        conn.status = status;
        conn.updated_at = Utc::now();
        Ok(())
    }
    
    /// Update connection health
    pub fn update_health(&self, id: &Uuid, health: ConnectionHealth) -> Result<(), ConnectorError> {
        let mut conn = self.connections.get_mut(id)
            .ok_or(ConnectorError::ConnectionNotFound(*id))?;
        
        // Check state before moving health
        let is_established = health.bgp_state == BgpState::Established;
        let current_status = conn.status;
        
        conn.health = health;
        conn.updated_at = Utc::now();
        
        // Update status based on health
        conn.status = if is_established {
            ConnectionStatus::Active
        } else if current_status == ConnectionStatus::Active {
            ConnectionStatus::Degraded
        } else {
            current_status
        };
        
        Ok(())
    }
    
    /// Delete connection
    pub async fn delete_connection(&self, id: &Uuid) -> Result<(), ConnectorError> {
        self.update_status(id, ConnectionStatus::Deleting)?;
        // In production: deprovision cloud resources
        self.connections.remove(id);
        Ok(())
    }
    
    /// Add route to connection
    pub async fn add_route(
        &self,
        connection_id: &Uuid,
        route: CloudRoute,
    ) -> Result<(), ConnectorError> {
        let mut conn = self.connections.get_mut(connection_id)
            .ok_or(ConnectorError::ConnectionNotFound(*connection_id))?;
        conn.routes.push(route.clone());
        self.route_manager.add_route(route);
        Ok(())
    }
    
    /// Configure failover between connections
    pub async fn configure_failover(
        &self,
        primary_id: &Uuid,
        backup_id: &Uuid,
    ) -> Result<(), ConnectorError> {
        let primary = self.get_connection(primary_id)
            .ok_or(ConnectorError::ConnectionNotFound(*primary_id))?;
        let backup = self.get_connection(backup_id)
            .ok_or(ConnectorError::ConnectionNotFound(*backup_id))?;
        
        // Configure primary with higher local preference
        self.route_manager.configure_failover_pair(&primary, &backup);
        
        Ok(())
    }
    
    /// Handle failover when connection goes down
    pub async fn handle_failover(&self, failed_id: &Uuid) -> Result<(), ConnectorError> {
        let failed = self.get_connection(failed_id)
            .ok_or(ConnectorError::ConnectionNotFound(*failed_id))?;
        
        // Find backup connections for same tenant
        let backups: Vec<_> = self.connections
            .iter()
            .filter(|r| r.tenant_id == failed.tenant_id && r.id != failed.id)
            .filter(|r| r.status == ConnectionStatus::Active)
            .map(|r| r.clone())
            .collect();
        
        if let Some(backup) = backups.first() {
            tracing::info!(
                "Failover from {} ({}) to {} ({})",
                failed.name, failed.cloud_provider.as_str(),
                backup.name, backup.cloud_provider.as_str()
            );
            self.route_manager.activate_backup(&failed, backup);
        } else {
            tracing::warn!("No backup connection available for {}", failed.name);
        }
        
        Ok(())
    }
    
    /// Generate BIRD BGP configuration
    pub fn generate_bird_config(&self, connection: &CloudConnection) -> String {
        let session_name = format!(
            "cloud_{}_{}",
            connection.cloud_provider.as_str().to_lowercase(),
            connection.id.to_string().replace('-', "_")[..8].to_string()
        );
        
        let advertised = connection.bgp_config.advertised_prefixes
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        
        format!(r#"
protocol bgp {session_name} {{
    description "{name} - {provider}";
    local as {our_asn};
    neighbor {cloud_ip} as {cloud_asn};
    
    {auth}
    
    ipv4 {{
        import filter {{
            bgp_local_pref = {local_pref};
            accept;
        }};
        export filter {{
            if net ~ [{advertised}] then accept;
            reject;
        }};
        import limit 1000 action block;
    }};
    
    graceful restart on;
    hold time 90;
    keepalive time 30;
}}
        "#,
            session_name = session_name,
            name = connection.name,
            provider = connection.cloud_provider.as_str(),
            our_asn = connection.bgp_config.our_asn,
            cloud_ip = connection.bgp_config.cloud_ip,
            cloud_asn = connection.bgp_config.cloud_asn,
            auth = connection.bgp_config.md5_auth.as_ref()
                .map(|k| format!("password \"{}\";", k))
                .unwrap_or_default(),
            local_pref = connection.bgp_config.local_preference,
            advertised = advertised,
        )
    }
    
    fn validate_request(&self, request: &CreateConnectionRequest) -> Result<(), ConnectorError> {
        if request.name.is_empty() {
            return Err(ConnectorError::ValidationError("Name is required".to_string()));
        }
        if request.bandwidth_mbps == 0 {
            return Err(ConnectorError::ValidationError("Bandwidth must be > 0".to_string()));
        }
        Ok(())
    }
}

impl Default for CloudConnectorService {
    fn default() -> Self {
        Self::new()
    }
}

/// Request to create a cloud connection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateConnectionRequest {
    pub name: String,
    pub cloud_provider: CloudProvider,
    pub connection_type: ConnectionType,
    pub bandwidth_mbps: u32,
    pub pop_location: String,
    pub cloud_region: String,
    pub bgp_config: BgpConfig,
    pub vlan_id: u16,
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("Connection not found: {0}")]
    ConnectionNotFound(Uuid),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Provisioning error: {0}")]
    ProvisioningError(String),
    
    #[error("BGP error: {0}")]
    BgpError(String),
    
    #[error("Quota exceeded")]
    QuotaExceeded,
    
    #[error("Provider error: {0}")]
    ProviderError(String),
}
