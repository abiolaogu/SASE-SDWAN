//! BGP Flowspec Integration
//!
//! RFC 5575 Flowspec rules for upstream mitigation.

use crate::{Attack, Protocol};
use std::net::IpAddr;

/// BGP Flowspec rule generator
pub struct FlowspecGenerator {
    /// Local ASN for communities
    local_asn: u32,
    /// Flowspec community for rate-limit
    rate_limit_community: String,
    /// Flowspec community for drop
    drop_community: String,
}

impl FlowspecGenerator {
    pub fn new(local_asn: u32) -> Self {
        Self {
            local_asn,
            rate_limit_community: format!("{}:5000", local_asn),
            drop_community: format!("{}:0", local_asn),
        }
    }
    
    /// Generate Flowspec NLRI for attack
    pub fn generate(&self, attack: &Attack) -> FlowspecRule {
        FlowspecRule {
            destination: attack.target.ip,
            destination_prefix: 32,
            source: None,
            protocol: Some(attack.target.protocol),
            source_port: None,
            destination_port: attack.target.port,
            tcp_flags: None,
            packet_length: None,
            dscp: None,
            fragment: None,
            action: FlowspecAction::RateLimit(
                attack.metrics.total_bps / 100 // 1% of attack traffic
            ),
        }
    }
    
    /// Generate BIRD configuration for Flowspec
    pub fn to_bird_config(&self, rule: &FlowspecRule) -> String {
        let mut config = String::new();
        
        config.push_str("flow4 {\n");
        config.push_str(&format!("    dst {}/{};\n", rule.destination, rule.destination_prefix));
        
        if let Some(src) = rule.source {
            config.push_str(&format!("    src {}/32;\n", src));
        }
        
        if let Some(proto) = &rule.protocol {
            config.push_str(&format!("    proto = {};\n", protocol_num(proto)));
        }
        
        if let Some(port) = rule.destination_port {
            config.push_str(&format!("    dport = {};\n", port));
        }
        
        if let Some(port) = rule.source_port {
            config.push_str(&format!("    sport = {};\n", port));
        }
        
        config.push_str("} then {\n");
        
        match &rule.action {
            FlowspecAction::Drop => {
                config.push_str("    discard;\n");
            }
            FlowspecAction::RateLimit(bps) => {
                config.push_str(&format!("    rate-limit {};\n", bps));
            }
            FlowspecAction::Redirect(rt) => {
                config.push_str(&format!("    redirect {};\n", rt));
            }
            FlowspecAction::Mark(dscp) => {
                config.push_str(&format!("    mark dscp {};\n", dscp));
            }
        }
        
        config.push_str("}\n");
        config
    }
    
    /// Generate Flowspec for multiple top sources
    pub fn generate_source_blocks(&self, attack: &Attack, limit: usize) -> Vec<FlowspecRule> {
        attack.sources.iter()
            .take(limit)
            .map(|source| FlowspecRule {
                destination: attack.target.ip,
                destination_prefix: 32,
                source: Some(source.ip),
                protocol: Some(attack.target.protocol),
                source_port: None,
                destination_port: attack.target.port,
                tcp_flags: None,
                packet_length: None,
                dscp: None,
                fragment: None,
                action: FlowspecAction::Drop,
            })
            .collect()
    }
}

/// Flowspec rule definition
#[derive(Debug, Clone)]
pub struct FlowspecRule {
    pub destination: IpAddr,
    pub destination_prefix: u8,
    pub source: Option<IpAddr>,
    pub protocol: Option<Protocol>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub packet_length: Option<(u16, u16)>,
    pub dscp: Option<u8>,
    pub fragment: Option<FragmentType>,
    pub action: FlowspecAction,
}

#[derive(Debug, Clone)]
pub enum FlowspecAction {
    Drop,
    RateLimit(u64), // bytes per second
    Redirect(String), // Route target
    Mark(u8), // DSCP value
}

#[derive(Debug, Clone, Copy)]
pub enum FragmentType {
    NotFragment,
    IsFragment,
    FirstFragment,
    LastFragment,
}

fn protocol_num(proto: &Protocol) -> u8 {
    match proto {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Icmp => 1,
        Protocol::Gre => 47,
        Protocol::Other(n) => *n,
    }
}

/// RTBH (Remote Triggered Black Hole) generator
pub struct RtbhGenerator {
    /// Blackhole community
    blackhole_community: String,
    /// Trigger prefix for RTBH
    trigger_prefix: String,
}

impl RtbhGenerator {
    pub fn new(local_asn: u32) -> Self {
        Self {
            blackhole_community: format!("{}:666", local_asn),
            trigger_prefix: "192.0.2.1".to_string(), // RFC 5737 documentation prefix
        }
    }
    
    /// Generate RTBH route for target IP
    pub fn generate(&self, target: IpAddr) -> String {
        format!(
            "route {}/32 via {} blackhole community {}",
            target,
            self.trigger_prefix,
            self.blackhole_community
        )
    }
    
    /// Generate BIRD static route for RTBH
    pub fn to_bird_static(&self, target: IpAddr) -> String {
        format!(
            r#"protocol static rtbh_{} {{
    route {}/32 blackhole {{
        bgp_community.add((65535, 666));
        bgp_community.add({});
    }};
}}"#,
            target.to_string().replace(".", "_"),
            target,
            self.blackhole_community
        )
    }
}
