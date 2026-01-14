//! Network Interface Management

use crate::{EdgeError, config::InterfaceConfig};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Interface manager
pub struct InterfaceManager {
    interfaces: Arc<RwLock<HashMap<String, Interface>>>,
}

impl InterfaceManager {
    pub fn new() -> Self {
        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure interfaces
    pub async fn configure(&self, configs: &[InterfaceConfig]) -> Result<(), EdgeError> {
        for config in configs {
            tracing::info!("Configuring interface: {}", config.name);
            
            let iface = Interface {
                name: config.name.clone(),
                role: config.role,
                ip_address: config.static_ip.clone(),
                gateway: config.gateway.clone(),
                status: InterfaceStatus::Up,
                stats: InterfaceStats::default(),
            };
            
            self.interfaces.write().insert(config.name.clone(), iface);
            
            // Apply configuration
            if config.dhcp {
                self.enable_dhcp(&config.name).await?;
            } else if let Some(ip) = &config.static_ip {
                self.set_static_ip(&config.name, ip).await?;
            }
        }
        
        Ok(())
    }

    /// Get interface by name
    pub fn get(&self, name: &str) -> Option<Interface> {
        self.interfaces.read().get(name).cloned()
    }

    /// Get all interfaces
    pub fn all(&self) -> Vec<Interface> {
        self.interfaces.read().values().cloned().collect()
    }

    /// Get interface stats
    pub fn stats(&self, name: &str) -> Option<InterfaceStats> {
        self.interfaces.read().get(name).map(|i| i.stats.clone())
    }

    /// Update interface stats
    pub fn update_stats(&self, name: &str, stats: InterfaceStats) {
        if let Some(iface) = self.interfaces.write().get_mut(name) {
            iface.stats = stats;
        }
    }

    async fn enable_dhcp(&self, name: &str) -> Result<(), EdgeError> {
        tracing::debug!("Enabling DHCP on {}", name);
        // dhclient <name>
        Ok(())
    }

    async fn set_static_ip(&self, name: &str, ip: &str) -> Result<(), EdgeError> {
        tracing::debug!("Setting static IP {} on {}", ip, name);
        // ip addr add <ip> dev <name>
        Ok(())
    }
}

impl Default for InterfaceManager {
    fn default() -> Self { Self::new() }
}

/// Network interface
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub role: crate::config::InterfaceRole,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
    pub status: InterfaceStatus,
    pub stats: InterfaceStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceStatus {
    Up,
    Down,
    Degraded,
}

/// Interface statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub latency_ms: u32,
    pub loss_percent: f32,
}
