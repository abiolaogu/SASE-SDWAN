//! VPP Integration for Backbone Traffic
//!
//! Configures VPP to use backbone links with VLAN interfaces,
//! policy routing, and traffic steering.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

use crate::{BackboneLink, BackboneProvider};
use crate::orchestrator::TrafficClass;

/// VPP integration errors
#[derive(Debug, Error)]
pub enum VppError {
    #[error("VPP connection failed: {0}")]
    Connection(String),
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
    #[error("Configuration failed: {0}")]
    ConfigFailed(String),
}

pub type Result<T> = std::result::Result<T, VppError>;

/// Traffic steering rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRule {
    pub id: String,
    pub traffic_class: TrafficClass,
    pub match_criteria: MatchCriteria,
    pub destination: IpAddr,
}

/// Match criteria for traffic classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCriteria {
    pub src_prefix: Option<String>,
    pub dst_prefix: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    pub dscp: Option<u8>,
}

/// VPP interface configuration for backbone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackboneInterface {
    pub sw_if_index: u32,
    pub parent_interface: String,
    pub vlan_id: u16,
    pub ip_address: IpAddr,
    pub mtu: u16,
    pub link_id: String,
}

/// VPP backbone configuration manager
pub struct VppBackboneConfig {
    /// VPP socket path
    vpp_socket: String,
    /// Configured backbone interfaces
    interfaces: Vec<BackboneInterface>,
    /// Backbone next-hop for policy routing
    backbone_next_hop: Option<IpAddr>,
    /// Internet next-hop for fallback
    internet_next_hop: Option<IpAddr>,
}

impl VppBackboneConfig {
    /// Create new VPP backbone config
    pub fn new(vpp_socket: String) -> Self {
        Self {
            vpp_socket,
            interfaces: Vec::new(),
            backbone_next_hop: None,
            internet_next_hop: None,
        }
    }

    /// Set backbone next-hop
    pub fn set_backbone_next_hop(&mut self, ip: IpAddr) {
        self.backbone_next_hop = Some(ip);
    }

    /// Set internet next-hop
    pub fn set_internet_next_hop(&mut self, ip: IpAddr) {
        self.internet_next_hop = Some(ip);
    }

    /// Configure VLAN interface for backbone link
    pub fn configure_backbone_interface(
        &mut self,
        link: &BackboneLink,
        parent_interface: &str,
        local_ip: IpAddr,
    ) -> Result<BackboneInterface> {
        let vlan_id = link.a_end.vlan_id;

        // Generate VPP CLI commands
        let commands = self.generate_interface_commands(
            parent_interface,
            vlan_id,
            local_ip,
            &link.id,
        );

        // In production, execute via VPP API
        tracing::info!("VPP commands for {}: {:?}", link.id, commands);

        let interface = BackboneInterface {
            sw_if_index: self.interfaces.len() as u32 + 100, // Placeholder
            parent_interface: parent_interface.to_string(),
            vlan_id,
            ip_address: local_ip,
            mtu: 9000,
            link_id: link.id.clone(),
        };

        self.interfaces.push(interface.clone());
        Ok(interface)
    }

    /// Generate VPP CLI commands for interface setup
    fn generate_interface_commands(
        &self,
        parent: &str,
        vlan: u16,
        ip: IpAddr,
        link_id: &str,
    ) -> Vec<String> {
        vec![
            format!("create sub-interface {} {}", parent, vlan),
            format!("set interface state {}.{} up", parent, vlan),
            format!("set interface ip address {}.{} {}/30", parent, vlan, ip),
            format!("set interface mtu 9000 {}.{}", parent, vlan),
            format!("comment {{ OSPB link: {} }}", link_id),
        ]
    }

    /// Configure policy routing for traffic classes
    pub fn configure_traffic_steering(&self, rules: &[TrafficRule]) -> Result<Vec<String>> {
        let mut commands = Vec::new();

        for rule in rules {
            // Create ACL for matching traffic
            let acl_rules = self.generate_acl_rules(&rule.match_criteria);
            commands.extend(acl_rules);

            // Create policy-based routing
            let next_hop = match rule.traffic_class {
                TrafficClass::VoiceVideo => self.backbone_next_hop,
                TrafficClass::Interactive => self.backbone_next_hop,
                TrafficClass::Bulk => self.internet_next_hop,
            };

            if let Some(nh) = next_hop {
                commands.push(format!(
                    "ip route add {} via {} table {}",
                    rule.destination,
                    nh,
                    rule.traffic_class as u32
                ));
            }
        }

        Ok(commands)
    }

    /// Generate ACL rules for traffic matching
    fn generate_acl_rules(&self, criteria: &MatchCriteria) -> Vec<String> {
        let mut rules = Vec::new();
        let mut rule_parts = Vec::new();

        if let Some(ref src) = criteria.src_prefix {
            rule_parts.push(format!("src {}", src));
        }
        if let Some(ref dst) = criteria.dst_prefix {
            rule_parts.push(format!("dst {}", dst));
        }
        if let Some(proto) = criteria.protocol {
            rule_parts.push(format!("proto {}", proto));
        }
        if let Some(dscp) = criteria.dscp {
            rule_parts.push(format!("dscp {}", dscp));
        }

        if !rule_parts.is_empty() {
            rules.push(format!("acl-plugin add rule permit {}", rule_parts.join(" ")));
        }

        rules
    }

    /// Generate complete VPP startup configuration
    pub fn generate_startup_config(&self) -> String {
        let mut config = String::new();

        config.push_str("# OSPB VPP Backbone Configuration\n\n");

        for iface in &self.interfaces {
            config.push_str(&format!(
                "# Interface for link: {}\n",
                iface.link_id
            ));
            config.push_str(&format!(
                "create sub-interface {} {}\n",
                iface.parent_interface, iface.vlan_id
            ));
            config.push_str(&format!(
                "set interface state {}.{} up\n",
                iface.parent_interface, iface.vlan_id
            ));
            config.push_str(&format!(
                "set interface ip address {}.{} {}/30\n",
                iface.parent_interface, iface.vlan_id, iface.ip_address
            ));
            config.push_str(&format!(
                "set interface mtu {} {}.{}\n\n",
                iface.mtu, iface.parent_interface, iface.vlan_id
            ));
        }

        config
    }

    /// Get all configured interfaces
    pub fn interfaces(&self) -> &[BackboneInterface] {
        &self.interfaces
    }
}

/// BGP configuration for backbone routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    pub local_asn: u32,
    pub router_id: IpAddr,
    pub neighbors: Vec<BgpNeighbor>,
}

/// BGP neighbor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNeighbor {
    pub address: IpAddr,
    pub remote_asn: u32,
    pub description: String,
    pub multihop: Option<u8>,
}

impl BgpConfig {
    /// Generate BIRD BGP configuration
    pub fn generate_bird_config(&self) -> String {
        let mut config = String::new();

        config.push_str("# OSPB BGP Configuration\n\n");
        config.push_str(&format!("router id {};\n\n", self.router_id));
        config.push_str(&format!("define MY_AS = {};\n\n", self.local_asn));

        for neighbor in &self.neighbors {
            config.push_str(&format!(
                "protocol bgp {} {{\n",
                neighbor.description.replace(' ', "_").to_lowercase()
            ));
            config.push_str(&format!("  local as MY_AS;\n"));
            config.push_str(&format!("  neighbor {} as {};\n", neighbor.address, neighbor.remote_asn));
            if let Some(multihop) = neighbor.multihop {
                config.push_str(&format!("  multihop {};\n", multihop));
            }
            config.push_str("  graceful restart on;\n");
            config.push_str("  ipv4 { import all; export all; };\n");
            config.push_str("}\n\n");
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_commands() {
        let config = VppBackboneConfig::new("/run/vpp/cli.sock".to_string());
        let commands = config.generate_interface_commands(
            "TenGigabitEthernet0/0/0",
            100,
            "10.100.0.1".parse().unwrap(),
            "nyc-lon",
        );

        assert_eq!(commands.len(), 5);
        assert!(commands[0].contains("create sub-interface"));
        assert!(commands[1].contains("state"));
        assert!(commands[2].contains("ip address"));
    }

    #[test]
    fn test_bgp_config() {
        let config = BgpConfig {
            local_asn: 65100,
            router_id: "10.0.0.1".parse().unwrap(),
            neighbors: vec![
                BgpNeighbor {
                    address: "10.0.0.2".parse().unwrap(),
                    remote_asn: 65100,
                    description: "OSPB NYC".to_string(),
                    multihop: Some(2),
                },
            ],
        };

        let bird_config = config.generate_bird_config();
        assert!(bird_config.contains("router id 10.0.0.1"));
        assert!(bird_config.contains("neighbor 10.0.0.2 as 65100"));
    }
}
