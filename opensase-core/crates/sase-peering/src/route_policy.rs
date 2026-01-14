//! Route Policy Management
//!
//! BGP route filtering, communities, and policy configuration.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::OPENSASE_ASN;

/// BGP community
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BgpCommunity {
    pub asn: u32,
    pub value: u32,
}

impl BgpCommunity {
    pub fn new(asn: u32, value: u32) -> Self {
        Self { asn, value }
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.asn, self.value)
    }
}

/// Standard OpenSASE communities
pub mod communities {
    use super::BgpCommunity;
    use crate::OPENSASE_ASN;

    /// Learned from IXP
    pub fn ixp_learned() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 100)
    }

    /// Learned from transit
    pub fn transit_learned() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 200)
    }

    /// Learned from customer
    pub fn customer_learned() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 300)
    }

    /// Do not announce to peers
    pub fn no_export_peers() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 1000)
    }

    /// Do not announce to transit
    pub fn no_export_transit() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 1001)
    }

    /// Blackhole
    pub fn blackhole() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 666)
    }

    /// Region: North America
    pub fn region_na() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 10)
    }

    /// Region: Europe
    pub fn region_eu() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 20)
    }

    /// Region: Asia Pacific
    pub fn region_ap() -> BgpCommunity {
        BgpCommunity::new(OPENSASE_ASN, 30)
    }
}

/// Route filter action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Accept,
    Reject,
    Modify,
}

/// Prefix filter rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixFilter {
    pub name: String,
    pub prefix: String,
    pub ge: Option<u8>,
    pub le: Option<u8>,
    pub action: FilterAction,
}

/// AS path filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsPathFilter {
    pub name: String,
    pub pattern: String, // Regex pattern
    pub action: FilterAction,
}

/// Complete route policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutePolicy {
    pub name: String,
    pub description: String,
    pub prefix_filters: Vec<PrefixFilter>,
    pub as_path_filters: Vec<AsPathFilter>,
    pub community_match: Vec<BgpCommunity>,
    pub community_set: Vec<BgpCommunity>,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub as_prepend: Option<u32>,
}

impl RoutePolicy {
    /// Create new route policy
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            prefix_filters: Vec::new(),
            as_path_filters: Vec::new(),
            community_match: Vec::new(),
            community_set: Vec::new(),
            local_pref: None,
            med: None,
            as_prepend: None,
        }
    }

    /// Add prefix filter
    pub fn add_prefix_filter(&mut self, filter: PrefixFilter) {
        self.prefix_filters.push(filter);
    }

    /// Set local preference
    pub fn set_local_pref(&mut self, pref: u32) {
        self.local_pref = Some(pref);
    }

    /// Add community to set
    pub fn add_community(&mut self, community: BgpCommunity) {
        self.community_set.push(community);
    }

    /// Generate BIRD filter code
    pub fn to_bird_filter(&self) -> String {
        let mut filter = format!("filter {} {{\n", self.name);
        filter.push_str(&format!("  # {}\n", self.description));
        
        // Prefix filters
        for pf in &self.prefix_filters {
            let range = match (pf.ge, pf.le) {
                (Some(ge), Some(le)) => format!("[{}, {}]", ge, le),
                (Some(ge), None) => format!("[{}, 32]", ge),
                (None, Some(le)) => format!("[0, {}]", le),
                (None, None) => String::new(),
            };
            
            let action = match pf.action {
                FilterAction::Accept => "accept",
                FilterAction::Reject => "reject",
                FilterAction::Modify => "{ }",
            };
            
            filter.push_str(&format!(
                "  if net ~ [ {}{} ] then {};\n",
                pf.prefix, 
                if range.is_empty() { "" } else { &format!("+{}", range) },
                action
            ));
        }
        
        // AS path filters
        for asf in &self.as_path_filters {
            let action = match asf.action {
                FilterAction::Accept => "accept",
                FilterAction::Reject => "reject",
                FilterAction::Modify => "{ }",
            };
            filter.push_str(&format!(
                "  if bgp_path ~ {} then {};\n",
                asf.pattern, action
            ));
        }
        
        // Set attributes
        if let Some(lp) = self.local_pref {
            filter.push_str(&format!("  bgp_local_pref = {};\n", lp));
        }
        
        if let Some(med) = self.med {
            filter.push_str(&format!("  bgp_med = {};\n", med));
        }
        
        // Set communities
        for comm in &self.community_set {
            filter.push_str(&format!(
                "  bgp_community.add(({}, {}));\n",
                comm.asn, comm.value
            ));
        }
        
        if let Some(prepend) = self.as_prepend {
            filter.push_str(&format!(
                "  bgp_path.prepend({});\n",
                prepend
            ));
        }
        
        filter.push_str("  accept;\n");
        filter.push_str("}\n");
        
        filter
    }
}

/// Standard policies
pub fn standard_import_policy() -> RoutePolicy {
    let mut policy = RoutePolicy::new("std_import", "Standard IXP import policy");
    
    // Reject bogons
    policy.add_prefix_filter(PrefixFilter {
        name: "reject_bogons".to_string(),
        prefix: "0.0.0.0/8+".to_string(),
        ge: None,
        le: None,
        action: FilterAction::Reject,
    });
    
    policy.add_prefix_filter(PrefixFilter {
        name: "reject_rfc1918_10".to_string(),
        prefix: "10.0.0.0/8+".to_string(),
        ge: None,
        le: None,
        action: FilterAction::Reject,
    });
    
    policy.add_prefix_filter(PrefixFilter {
        name: "reject_rfc1918_172".to_string(),
        prefix: "172.16.0.0/12+".to_string(),
        ge: None,
        le: None,
        action: FilterAction::Reject,
    });
    
    policy.add_prefix_filter(PrefixFilter {
        name: "reject_rfc1918_192".to_string(),
        prefix: "192.168.0.0/16+".to_string(),
        ge: None,
        le: None,
        action: FilterAction::Reject,
    });
    
    // Set community
    policy.add_community(communities::ixp_learned());
    policy.set_local_pref(150);
    
    policy
}

/// Standard export policy
pub fn standard_export_policy() -> RoutePolicy {
    let mut policy = RoutePolicy::new("std_export", "Standard IXP export policy");
    
    // Only export our prefixes
    policy.add_prefix_filter(PrefixFilter {
        name: "our_prefixes".to_string(),
        prefix: "203.0.113.0/24".to_string(), // Placeholder for OpenSASE prefixes
        ge: None,
        le: Some(24),
        action: FilterAction::Accept,
    });
    
    policy
}

/// Generate complete BIRD configuration
pub fn generate_bird_config(
    router_id: IpAddr,
    policies: &[RoutePolicy],
) -> String {
    let mut config = String::new();
    
    config.push_str("# OpenSASE Peering Engine - BIRD Configuration\n\n");
    config.push_str(&format!("router id {};\n\n", router_id));
    config.push_str(&format!("define MY_AS = {};\n", OPENSASE_ASN));
    config.push_str("define MY_PREFIXES = [ 203.0.113.0/24 ];\n\n");
    
    // Protocols
    config.push_str("protocol device { }\n\n");
    config.push_str("protocol direct { ipv4; ipv6; }\n\n");
    config.push_str("protocol kernel { ipv4 { export all; }; }\n\n");
    
    // Generate filters
    for policy in policies {
        config.push_str(&policy.to_bird_filter());
        config.push_str("\n");
    }
    
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_string() {
        let comm = BgpCommunity::new(65100, 100);
        assert_eq!(comm.to_string(), "65100:100");
    }

    #[test]
    fn test_route_policy() {
        let policy = standard_import_policy();
        let bird = policy.to_bird_filter();
        
        assert!(bird.contains("filter std_import"));
        assert!(bird.contains("reject"));
        assert!(bird.contains("bgp_local_pref"));
    }

    #[test]
    fn test_bird_config_generation() {
        let policies = vec![standard_import_policy(), standard_export_policy()];
        let config = generate_bird_config("10.0.0.1".parse().unwrap(), &policies);
        
        assert!(config.contains("router id 10.0.0.1"));
        assert!(config.contains(&format!("define MY_AS = {}", OPENSASE_ASN)));
    }
}
