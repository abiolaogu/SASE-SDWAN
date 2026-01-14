//! IXP Management
//!
//! Manages IXP port connections and configuration.

use crate::{IxpPort, IxpConnectionStatus, InternetExchange, OPENSASE_ASN};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// IXP port request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IxpPortRequest {
    pub ixp_id: u32,
    pub pop_name: String,
    pub speed_mbps: u32,
    pub request_ipv4: bool,
    pub request_ipv6: bool,
    pub vlan_preference: Option<u16>,
    pub contact_email: String,
    pub technical_contact: String,
}

/// IXP port configuration generated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IxpPortConfig {
    pub port: IxpPort,
    pub vpp_commands: Vec<String>,
    pub bird_config: String,
}

/// IXP manager
pub struct IxpManager {
    ports: HashMap<String, IxpPort>,
    exchanges: HashMap<u32, InternetExchange>,
}

impl IxpManager {
    /// Create new IXP manager
    pub fn new() -> Self {
        Self {
            ports: HashMap::new(),
            exchanges: HashMap::new(),
        }
    }

    /// Register an IXP
    pub fn register_ixp(&mut self, ixp: InternetExchange) {
        self.exchanges.insert(ixp.id, ixp);
    }

    /// Add IXP port
    pub fn add_port(&mut self, port: IxpPort) {
        self.ports.insert(port.id.clone(), port);
    }

    /// Get port by ID
    pub fn get_port(&self, port_id: &str) -> Option<&IxpPort> {
        self.ports.get(port_id)
    }

    /// Get all ports at an IXP
    pub fn get_ixp_ports(&self, ixp_id: u32) -> Vec<&IxpPort> {
        self.ports.values()
            .filter(|p| p.ixp_id == ixp_id)
            .collect()
    }

    /// Get active ports
    pub fn active_ports(&self) -> Vec<&IxpPort> {
        self.ports.values()
            .filter(|p| p.is_active())
            .collect()
    }

    /// Generate port configuration
    pub fn generate_port_config(&self, port: &IxpPort) -> IxpPortConfig {
        let vpp_commands = self.generate_vpp_commands(port);
        let bird_config = self.generate_bird_config(port);
        
        IxpPortConfig {
            port: port.clone(),
            vpp_commands,
            bird_config,
        }
    }

    /// Generate VPP configuration commands
    fn generate_vpp_commands(&self, port: &IxpPort) -> Vec<String> {
        let mut commands = Vec::new();
        
        // Create VLAN sub-interface
        commands.push(format!(
            "create sub-interface TenGigabitEthernet0/0/0 {}",
            port.vlan_id
        ));
        
        commands.push(format!(
            "set interface state TenGigabitEthernet0/0/0.{} up",
            port.vlan_id
        ));
        
        // Configure IPv4
        if let Some(ipv4) = &port.ipv4_address {
            commands.push(format!(
                "set interface ip address TenGigabitEthernet0/0/0.{} {}/24",
                port.vlan_id, ipv4
            ));
        }
        
        // Configure IPv6
        if let Some(ipv6) = &port.ipv6_address {
            commands.push(format!(
                "set interface ip address TenGigabitEthernet0/0/0.{} {}/64",
                port.vlan_id, ipv6
            ));
        }
        
        // Set MTU (IXPs typically support jumbo frames)
        commands.push(format!(
            "set interface mtu 9000 TenGigabitEthernet0/0/0.{}",
            port.vlan_id
        ));
        
        commands
    }

    /// Generate BIRD BGP configuration
    fn generate_bird_config(&self, port: &IxpPort) -> String {
        let ixp_name = port.ixp_name.replace(' ', "_").replace('-', "_").to_lowercase();
        
        format!(r#"
# OSPE IXP Configuration: {}
# Port: {} @ {}

define IXP_{}_IP4 = {};
define IXP_{}_IP6 = {};

filter ixp_{}_import {{
    # Accept all from IXP route servers
    if bgp_path.len > 64 then reject;
    if net.len < 8 || net.len > 24 then reject;
    accept;
}}

filter ixp_{}_export {{
    # Export our prefixes to IXP
    if source = RTS_BGP && bgp_local_pref >= 100 then accept;
    if source = RTS_STATIC then accept;
    reject;
}}

template bgp ixp_{}_peer {{
    local as {};
    source address IXP_{}_IP4;
    graceful restart on;
    
    ipv4 {{
        import filter ixp_{}_import;
        export filter ixp_{}_export;
        import limit 100000 action restart;
    }};
}}
"#,
            port.ixp_name,
            port.id,
            port.pop_name,
            ixp_name.to_uppercase(),
            port.ipv4_address.map(|ip| ip.to_string()).unwrap_or_else(|| "0.0.0.0".to_string()),
            ixp_name.to_uppercase(),
            port.ipv6_address.map(|ip| ip.to_string()).unwrap_or_else(|| "::".to_string()),
            ixp_name,
            ixp_name,
            ixp_name,
            OPENSASE_ASN,
            ixp_name.to_uppercase(),
            ixp_name,
            ixp_name,
        )
    }

    /// Calculate total IXP presence
    pub fn ixp_presence_summary(&self) -> IxpPresenceSummary {
        let active_ports = self.active_ports();
        let unique_ixps: std::collections::HashSet<u32> = active_ports.iter().map(|p| p.ixp_id).collect();
        let total_bandwidth: u32 = active_ports.iter().map(|p| p.speed_mbps).sum();
        let monthly_cost: f64 = active_ports.iter().map(|p| p.monthly_cost).sum();
        
        IxpPresenceSummary {
            total_ixps: unique_ixps.len(),
            total_ports: active_ports.len(),
            total_bandwidth_gbps: total_bandwidth / 1000,
            monthly_cost,
            countries: self.count_countries(),
        }
    }

    /// Count unique countries
    fn count_countries(&self) -> usize {
        self.exchanges.values()
            .map(|e| &e.country)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }
}

impl Default for IxpManager {
    fn default() -> Self {
        Self::new()
    }
}

/// IXP presence summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IxpPresenceSummary {
    pub total_ixps: usize,
    pub total_ports: usize,
    pub total_bandwidth_gbps: u32,
    pub monthly_cost: f64,
    pub countries: usize,
}

/// Recommended port speeds for IXPs
pub fn recommended_port_speed(ixp_member_count: u32) -> u32 {
    match ixp_member_count {
        0..=100 => 1000,    // 1 Gbps for small IXPs
        101..=500 => 10000, // 10 Gbps for medium IXPs
        _ => 100000,        // 100 Gbps for major IXPs
    }
}

/// Estimate monthly cost for IXP port
pub fn estimate_port_cost(ixp_name: &str, speed_mbps: u32) -> f64 {
    // Base cost varies by IXP reputation and location
    let base_multiplier = if ixp_name.contains("DE-CIX") || ixp_name.contains("AMS-IX") {
        1.5
    } else if ixp_name.contains("LINX") || ixp_name.contains("Equinix") {
        1.3
    } else {
        1.0
    };
    
    let speed_cost = match speed_mbps {
        1000 => 500.0,
        10000 => 2000.0,
        100000 => 8000.0,
        _ => (speed_mbps as f64) * 0.5,
    };
    
    speed_cost * base_multiplier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ixp_manager() {
        let mut manager = IxpManager::new();
        
        manager.add_port(IxpPort {
            id: "port-1".to_string(),
            ixp_id: 26,
            ixp_name: "DE-CIX Frankfurt".to_string(),
            pop_name: "fra1".to_string(),
            speed_mbps: 10000,
            ipv4_address: Some("80.81.192.100".parse().unwrap()),
            ipv6_address: Some("2001:7f8::65100".parse().unwrap()),
            vlan_id: 100,
            status: IxpConnectionStatus::Active,
            monthly_cost: 3000.0,
        });
        
        assert_eq!(manager.active_ports().len(), 1);
    }

    #[test]
    fn test_port_cost_estimation() {
        let decix_10g = estimate_port_cost("DE-CIX Frankfurt", 10000);
        let generic_10g = estimate_port_cost("Local IX", 10000);
        
        assert!(decix_10g > generic_10g);
    }
}
