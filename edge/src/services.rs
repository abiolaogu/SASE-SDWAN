//! Local Services (DHCP, DNS, NTP)

use crate::EdgeError;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Local services manager
pub struct LocalServices {
    dhcp: Arc<RwLock<DhcpServer>>,
    dns: Arc<RwLock<DnsRelay>>,
}

impl LocalServices {
    pub fn new() -> Self {
        Self {
            dhcp: Arc::new(RwLock::new(DhcpServer::new())),
            dns: Arc::new(RwLock::new(DnsRelay::new())),
        }
    }

    /// Configure DHCP for VLAN
    pub fn configure_dhcp(&self, vlan: &str, config: DhcpConfig) -> Result<(), EdgeError> {
        tracing::info!("Configuring DHCP for VLAN {}", vlan);
        self.dhcp.write().add_pool(vlan.to_string(), config);
        Ok(())
    }

    /// Configure DNS relay
    pub fn configure_dns(&self, config: DnsConfig) -> Result<(), EdgeError> {
        tracing::info!("Configuring DNS relay");
        self.dns.write().configure(config);
        Ok(())
    }

    /// Get DHCP leases
    pub fn get_leases(&self, vlan: &str) -> Vec<DhcpLease> {
        self.dhcp.read().get_leases(vlan)
    }

    /// Start all services
    pub async fn start(&self) -> Result<(), EdgeError> {
        self.dhcp.write().start().await?;
        self.dns.write().start().await?;
        Ok(())
    }

    /// Stop all services
    pub async fn stop(&self) -> Result<(), EdgeError> {
        self.dhcp.write().stop().await?;
        self.dns.write().stop().await?;
        Ok(())
    }
}

impl Default for LocalServices {
    fn default() -> Self { Self::new() }
}

/// DHCP Server
struct DhcpServer {
    pools: HashMap<String, DhcpConfig>,
    leases: HashMap<String, Vec<DhcpLease>>,
    running: bool,
}

impl DhcpServer {
    fn new() -> Self {
        Self {
            pools: HashMap::new(),
            leases: HashMap::new(),
            running: false,
        }
    }

    fn add_pool(&mut self, vlan: String, config: DhcpConfig) {
        self.pools.insert(vlan, config);
    }

    fn get_leases(&self, vlan: &str) -> Vec<DhcpLease> {
        self.leases.get(vlan).cloned().unwrap_or_default()
    }

    async fn start(&mut self) -> Result<(), EdgeError> {
        tracing::debug!("Starting DHCP server");
        self.running = true;
        // In production: dnsmasq or kea-dhcp
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), EdgeError> {
        self.running = false;
        Ok(())
    }
}

/// DNS Relay
struct DnsRelay {
    config: Option<DnsConfig>,
    running: bool,
}

impl DnsRelay {
    fn new() -> Self {
        Self { config: None, running: false }
    }

    fn configure(&mut self, config: DnsConfig) {
        self.config = Some(config);
    }

    async fn start(&mut self) -> Result<(), EdgeError> {
        tracing::debug!("Starting DNS relay");
        self.running = true;
        // In production: unbound
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), EdgeError> {
        self.running = false;
        Ok(())
    }
}

/// DHCP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub interface: String,
    pub range_start: String,
    pub range_end: String,
    pub subnet_mask: String,
    pub gateway: String,
    pub dns_servers: Vec<String>,
    pub lease_time_hours: u32,
    pub reservations: Vec<DhcpReservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpReservation {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
}

/// DHCP lease
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: String,
    pub expires_at: u64,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub upstream_servers: Vec<String>,
    pub local_domain: String,
    pub cache_size: u32,
    pub blocklists: Vec<String>,
}
