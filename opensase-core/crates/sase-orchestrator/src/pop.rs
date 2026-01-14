//! PoP Definition and Types
//!
//! Defines Points of Presence (PoPs) deployed on dedicated servers.

use serde::{Deserialize, Serialize};
use crate::provider::{DedicatedProvider, CloudProvider};

/// PoP Definition - Deployable unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopDefinition {
    /// Unique PoP identifier
    pub pop_id: String,
    /// Geographic region
    pub region: Region,
    /// Cloud provider
    pub provider: CloudProvider,
    /// PoP tier (Core/Edge)
    pub tier: PopTier,
    /// Capacity specification
    pub capacity: CapacitySpec,
    /// Services to deploy
    pub services: Vec<ServiceConfig>,
    /// Network configuration
    pub network: NetworkConfig,
    /// Tags for organization
    pub tags: Vec<String>,
}

impl PopDefinition {
    /// Create new PoP definition
    pub fn new(pop_id: &str, region: Region, provider: CloudProvider, tier: PopTier) -> Self {
        Self {
            pop_id: pop_id.to_string(),
            region,
            provider,
            tier,
            capacity: CapacitySpec::default(),
            services: Vec::new(),
            network: NetworkConfig::default(),
            tags: Vec::new(),
        }
    }

    /// Add service
    pub fn with_service(mut self, service: ServiceConfig) -> Self {
        self.services.push(service);
        self
    }

    /// Set capacity
    pub fn with_capacity(mut self, capacity: CapacitySpec) -> Self {
        self.capacity = capacity;
        self
    }

    /// Validate definition
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.pop_id.is_empty() {
            return Err(ValidationError::InvalidPopId);
        }
        if self.services.is_empty() {
            return Err(ValidationError::NoServices);
        }
        Ok(())
    }
}

/// Geographic region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    /// Region code (e.g., us-east-1)
    pub code: String,
    /// Display name
    pub name: String,
    /// Continent
    pub continent: Continent,
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
}

impl Region {
    pub fn new(code: &str, name: &str, continent: Continent, lat: f64, lon: f64) -> Self {
        Self {
            code: code.to_string(),
            name: name.to_string(),
            continent,
            latitude: lat,
            longitude: lon,
        }
    }
}

/// Continent
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Continent {
    NorthAmerica,
    SouthAmerica,
    Europe,
    Asia,
    Africa,
    Oceania,
}

/// PoP Tier
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PopTier {
    /// Full stack - all services
    Core,
    /// Tunnel/proxy only
    Edge,
    /// Caching only
    Cache,
}

impl PopTier {
    pub fn required_services(&self) -> Vec<&'static str> {
        match self {
            PopTier::Core => vec!["gateway", "policy", "dlp", "ips", "tunnel", "cache"],
            PopTier::Edge => vec!["tunnel", "proxy"],
            PopTier::Cache => vec!["cache", "proxy"],
        }
    }
}

/// Capacity specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacitySpec {
    /// vCPUs
    pub vcpus: u32,
    /// Memory in GB
    pub memory_gb: u32,
    /// Storage in GB
    pub storage_gb: u32,
    /// Network bandwidth in Gbps
    pub bandwidth_gbps: u32,
    /// Max concurrent connections
    pub max_connections: u64,
    /// Instance count (for scaling)
    pub instance_count: u32,
}

impl Default for CapacitySpec {
    fn default() -> Self {
        Self {
            vcpus: 4,
            memory_gb: 8,
            storage_gb: 100,
            bandwidth_gbps: 10,
            max_connections: 100_000,
            instance_count: 2,
        }
    }
}

impl CapacitySpec {
    /// Small edge PoP
    pub fn small() -> Self {
        Self {
            vcpus: 2,
            memory_gb: 4,
            storage_gb: 50,
            bandwidth_gbps: 1,
            max_connections: 10_000,
            instance_count: 1,
        }
    }

    /// Medium regional PoP
    pub fn medium() -> Self {
        Self::default()
    }

    /// Large core PoP
    pub fn large() -> Self {
        Self {
            vcpus: 16,
            memory_gb: 32,
            storage_gb: 500,
            bandwidth_gbps: 40,
            max_connections: 1_000_000,
            instance_count: 4,
        }
    }
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Service name
    pub name: String,
    /// Docker image
    pub image: String,
    /// Port mappings
    pub ports: Vec<PortMapping>,
    /// Environment variables
    pub env: Vec<(String, String)>,
    /// Resource limits
    pub resources: ResourceLimits,
    /// Health check
    pub health_check: Option<HealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_limit: String,
    pub memory_limit: String,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_limit: "1".to_string(),
            memory_limit: "1Gi".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub endpoint: String,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// VPC CIDR
    pub vpc_cidr: String,
    /// Subnet CIDRs
    pub subnets: Vec<SubnetConfig>,
    /// Enable anycast
    pub anycast_enabled: bool,
    /// Anycast IP (if enabled)
    pub anycast_ip: Option<String>,
    /// BGP ASN
    pub bgp_asn: Option<u32>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            vpc_cidr: "10.0.0.0/16".to_string(),
            subnets: vec![
                SubnetConfig {
                    name: "public".to_string(),
                    cidr: "10.0.1.0/24".to_string(),
                    is_public: true,
                },
                SubnetConfig {
                    name: "private".to_string(),
                    cidr: "10.0.2.0/24".to_string(),
                    is_public: false,
                },
            ],
            anycast_enabled: false,
            anycast_ip: None,
            bgp_asn: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetConfig {
    pub name: String,
    pub cidr: String,
    pub is_public: bool,
}

/// Validation errors
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid PoP ID")]
    InvalidPopId,
    #[error("no services defined")]
    NoServices,
    #[error("invalid capacity: {0}")]
    InvalidCapacity(String),
}

/// PoP status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PopStatus {
    Pending,
    Provisioning,
    Running,
    Degraded,
    Maintenance,
    Failed,
    Terminated,
}

/// Live PoP instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopInstance {
    pub definition: PopDefinition,
    pub status: PopStatus,
    pub public_ips: Vec<String>,
    pub private_ips: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub health_score: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop_definition() {
        // Using Hetzner datacenter instead of hyperscaler
        let region = Region::new("fsn1", "Falkenstein", Continent::Europe, 50.47, 12.37);
        let pop = PopDefinition::new("pop-eu-fsn1", region, DedicatedProvider::Hetzner, PopTier::Core)
            .with_capacity(CapacitySpec::large())
            .with_service(ServiceConfig {
                name: "gateway".into(),
                image: "opensase/gateway:latest".into(),
                ports: vec![PortMapping { container_port: 443, host_port: 443, protocol: "tcp".into() }],
                env: vec![],
                resources: ResourceLimits::default(),
                health_check: None,
            });

        assert!(pop.validate().is_ok());
    }

    #[test]
    fn test_capacity_specs() {
        let small = CapacitySpec::small();
        let large = CapacitySpec::large();
        
        assert!(large.vcpus > small.vcpus);
        assert!(large.bandwidth_gbps > small.bandwidth_gbps);
    }
}
