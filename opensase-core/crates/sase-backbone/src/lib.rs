//! OpenSASE Private Backbone (OSPB) - Rust Management API
//!
//! Provides programmatic control over Megaport and PacketFabric
//! for on-demand VXC provisioning and bandwidth management.

pub mod orchestrator;
pub mod vpp_integration;
pub mod cost_optimizer;

pub use orchestrator::*;
pub use vpp_integration::*;
pub use cost_optimizer::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Backbone provider types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackboneProvider {
    Megaport,
    PacketFabric,
}

/// Connection topology
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Topology {
    #[default]
    FullMesh,
    HubSpoke,
    RegionalMesh,
}

/// PoP tier classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PopTier {
    /// Dual-provider redundancy (Megaport + PacketFabric)
    Tier1,
    /// Single provider with high bandwidth
    Tier2,
    /// Single provider, cost-optimized
    Tier3,
}

/// Port status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    Provisioning,
    Active,
    Degraded,
    Down,
    Decommissioned,
}

/// VXC (Virtual Cross-Connect) status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VxcStatus {
    Pending,
    Provisioning,
    Active,
    Degraded,
    Down,
}

/// Backbone port definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackbonePort {
    pub id: String,
    pub pop_name: String,
    pub provider: BackboneProvider,
    pub location_id: String,
    pub speed_mbps: u32,
    pub vlan_id: u16,
    pub status: PortStatus,
    pub monthly_cost_usd: f64,
}

/// VXC connection definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VxcConnection {
    pub id: String,
    pub name: String,
    pub provider: BackboneProvider,
    pub a_end: VxcEndpoint,
    pub z_end: VxcEndpoint,
    pub bandwidth_mbps: u32,
    pub burst_mbps: Option<u32>,
    pub status: VxcStatus,
    pub latency_ms: Option<f32>,
    pub monthly_cost_usd: f64,
}

/// VXC endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VxcEndpoint {
    pub port_id: String,
    pub pop_name: String,
    pub vlan_id: u16,
}

/// Backbone configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackboneConfig {
    pub name: String,
    pub topology: Topology,
    pub primary_provider: BackboneProvider,
    pub enable_redundancy: bool,
    pub max_latency_ms: u32,
    pub optimization_mode: OptimizationMode,
}

/// Cost optimization mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OptimizationMode {
    Performance,
    #[default]
    Balanced,
    Cost,
}

/// Backbone mesh state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackboneMesh {
    pub name: String,
    pub config: BackboneConfig,
    pub ports: HashMap<String, BackbonePort>,
    pub connections: HashMap<String, VxcConnection>,
    pub regional_hubs: HashMap<String, String>,
}

impl BackboneMesh {
    /// Create a new backbone mesh
    pub fn new(config: BackboneConfig) -> Self {
        Self {
            name: config.name.clone(),
            config,
            ports: HashMap::new(),
            connections: HashMap::new(),
            regional_hubs: HashMap::new(),
        }
    }

    /// Add a port to the mesh
    pub fn add_port(&mut self, port: BackbonePort) {
        self.ports.insert(port.pop_name.clone(), port);
    }

    /// Add a VXC connection
    pub fn add_connection(&mut self, connection: VxcConnection) {
        let key = format!("{}-{}", connection.a_end.pop_name, connection.z_end.pop_name);
        self.connections.insert(key, connection);
    }

    /// Get all active connections
    pub fn active_connections(&self) -> Vec<&VxcConnection> {
        self.connections
            .values()
            .filter(|c| c.status == VxcStatus::Active)
            .collect()
    }

    /// Calculate total monthly cost
    pub fn monthly_cost(&self) -> f64 {
        let port_cost: f64 = self.ports.values().map(|p| p.monthly_cost_usd).sum();
        let vxc_cost: f64 = self.connections.values().map(|c| c.monthly_cost_usd).sum();
        port_cost + vxc_cost
    }

    /// Get connections for a specific PoP
    pub fn pop_connections(&self, pop_name: &str) -> Vec<&VxcConnection> {
        self.connections
            .values()
            .filter(|c| c.a_end.pop_name == pop_name || c.z_end.pop_name == pop_name)
            .collect()
    }

    /// Calculate average latency across all connections
    pub fn average_latency(&self) -> Option<f32> {
        let latencies: Vec<f32> = self
            .connections
            .values()
            .filter_map(|c| c.latency_ms)
            .collect();
        
        if latencies.is_empty() {
            None
        } else {
            Some(latencies.iter().sum::<f32>() / latencies.len() as f32)
        }
    }
}

/// Regional groups for routing optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalGroup {
    pub region: String,
    pub hub_pop: String,
    pub member_pops: Vec<String>,
}

/// Bandwidth utilization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthMetrics {
    pub connection_id: String,
    pub current_mbps: f64,
    pub peak_mbps: f64,
    pub average_mbps: f64,
    pub utilization_percent: f32,
    pub timestamp: i64,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub pop_name: String,
    pub provider: BackboneProvider,
    pub port_status: PortStatus,
    pub vxc_count: usize,
    pub active_vxcs: usize,
    pub avg_latency_ms: Option<f32>,
    pub packet_loss_percent: f32,
    pub healthy: bool,
}

impl HealthCheck {
    pub fn is_critical(&self) -> bool {
        !self.healthy || self.packet_loss_percent > 1.0
    }
}

/// Failover event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub timestamp: i64,
    pub affected_pop: String,
    pub from_provider: BackboneProvider,
    pub to_provider: BackboneProvider,
    pub reason: String,
    pub duration_ms: u64,
    pub success: bool,
}

/// Cost breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBreakdown {
    pub period: String,
    pub megaport_ports: f64,
    pub megaport_vxcs: f64,
    pub packetfabric_ports: f64,
    pub packetfabric_vcs: f64,
    pub total: f64,
    pub vs_internet_estimate: f64,
    pub savings_percent: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backbone_mesh_creation() {
        let config = BackboneConfig {
            name: "ospb-test".to_string(),
            topology: Topology::FullMesh,
            primary_provider: BackboneProvider::Megaport,
            enable_redundancy: true,
            max_latency_ms: 50,
            optimization_mode: OptimizationMode::Balanced,
        };
        
        let mesh = BackboneMesh::new(config);
        assert_eq!(mesh.name, "ospb-test");
        assert!(mesh.ports.is_empty());
        assert!(mesh.connections.is_empty());
    }

    #[test]
    fn test_add_port_and_connection() {
        let config = BackboneConfig {
            name: "test".to_string(),
            topology: Topology::FullMesh,
            primary_provider: BackboneProvider::Megaport,
            enable_redundancy: false,
            max_latency_ms: 100,
            optimization_mode: OptimizationMode::Cost,
        };
        
        let mut mesh = BackboneMesh::new(config);
        
        mesh.add_port(BackbonePort {
            id: "port-1".to_string(),
            pop_name: "nyc".to_string(),
            provider: BackboneProvider::Megaport,
            location_id: "Equinix NY5".to_string(),
            speed_mbps: 10000,
            vlan_id: 100,
            status: PortStatus::Active,
            monthly_cost_usd: 1500.0,
        });
        
        mesh.add_port(BackbonePort {
            id: "port-2".to_string(),
            pop_name: "lon".to_string(),
            provider: BackboneProvider::Megaport,
            location_id: "Equinix LD5".to_string(),
            speed_mbps: 10000,
            vlan_id: 101,
            status: PortStatus::Active,
            monthly_cost_usd: 1500.0,
        });
        
        mesh.add_connection(VxcConnection {
            id: "vxc-1".to_string(),
            name: "NYC-LON".to_string(),
            provider: BackboneProvider::Megaport,
            a_end: VxcEndpoint {
                port_id: "port-1".to_string(),
                pop_name: "nyc".to_string(),
                vlan_id: 100,
            },
            z_end: VxcEndpoint {
                port_id: "port-2".to_string(),
                pop_name: "lon".to_string(),
                vlan_id: 101,
            },
            bandwidth_mbps: 5000,
            burst_mbps: Some(10000),
            status: VxcStatus::Active,
            latency_ms: Some(75.0),
            monthly_cost_usd: 2000.0,
        });
        
        assert_eq!(mesh.ports.len(), 2);
        assert_eq!(mesh.connections.len(), 1);
        assert_eq!(mesh.monthly_cost(), 5000.0);
        assert!(mesh.average_latency().is_some());
    }

    #[test]
    fn test_health_check() {
        let check = HealthCheck {
            pop_name: "nyc".to_string(),
            provider: BackboneProvider::Megaport,
            port_status: PortStatus::Active,
            vxc_count: 5,
            active_vxcs: 5,
            avg_latency_ms: Some(10.5),
            packet_loss_percent: 0.01,
            healthy: true,
        };
        
        assert!(!check.is_critical());
        assert!(check.healthy);
    }
}
