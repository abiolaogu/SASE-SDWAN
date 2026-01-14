//! BIRD 2 BGP Configuration Generator
//!
//! Comprehensive BIRD 2 configuration for IXP peering,
//! route servers, and bilateral sessions.

use crate::{OPENSASE_ASN, InternetExchange, PeeringSession, IxpPort};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// BIRD 2 configuration generator
pub struct Bird2Config {
    pub router_id: IpAddr,
    pub local_asn: u32,
    pub prefixes_v4: Vec<String>,
    pub prefixes_v6: Vec<String>,
    pub ixp_ports: Vec<IxpPort>,
    pub sessions: Vec<PeeringSession>,
}

impl Bird2Config {
    /// Create new BIRD config generator
    pub fn new(router_id: IpAddr, prefixes_v4: Vec<String>, prefixes_v6: Vec<String>) -> Self {
        Self {
            router_id,
            local_asn: OPENSASE_ASN,
            prefixes_v4,
            prefixes_v6,
            ixp_ports: Vec::new(),
            sessions: Vec::new(),
        }
    }

    /// Add IXP port
    pub fn add_ixp_port(&mut self, port: IxpPort) {
        self.ixp_ports.push(port);
    }

    /// Add peering session
    pub fn add_session(&mut self, session: PeeringSession) {
        self.sessions.push(session);
    }

    /// Generate complete BIRD 2 configuration
    pub fn generate(&self) -> String {
        let mut config = String::new();
        
        config.push_str(&self.generate_header());
        config.push_str(&self.generate_constants());
        config.push_str(&self.generate_protocols());
        config.push_str(&self.generate_filters());
        config.push_str(&self.generate_templates());
        config.push_str(&self.generate_ixp_sessions());
        
        config
    }

    /// Generate configuration header
    fn generate_header(&self) -> String {
        format!(r#"################################################################################
# OpenSASE Peering Engine - BIRD 2 Configuration
# Generated for AS{} 
# Router ID: {}
################################################################################

log syslog all;
log "/var/log/bird.log" {{ debug, trace, info, remote, warning, error, auth, fatal, bug }};

router id {};
hostname "ospe-router";

# Watchdog timer
watchdog warning 5 s;
watchdog timeout 30 s;

"#, self.local_asn, self.router_id, self.router_id)
    }

    /// Generate constants and definitions
    fn generate_constants(&self) -> String {
        let v4_prefixes = self.prefixes_v4.iter()
            .map(|p| format!("    {}", p))
            .collect::<Vec<_>>()
            .join(",\n");
        
        let v6_prefixes = self.prefixes_v6.iter()
            .map(|p| format!("    {}", p))
            .collect::<Vec<_>>()
            .join(",\n");

        format!(r#"################################################################################
# Constants and Definitions
################################################################################

define MY_AS = {};
define MY_ROUTER_ID = {};

# Our IPv4 prefixes
define MY_PREFIXES_V4 = [
{}
];

# Our IPv6 prefixes  
define MY_PREFIXES_V6 = [
{}
];

# BGP Communities
define IXP_LEARNED         = ({}, 100);
define TRANSIT_LEARNED     = ({}, 200);
define CUSTOMER_LEARNED    = ({}, 300);
define NO_EXPORT_PEERS     = ({}, 1000);
define NO_EXPORT_TRANSIT   = ({}, 1001);
define BLACKHOLE           = ({}, 666);

# Regional communities
define REGION_NA   = ({}, 10);
define REGION_EU   = ({}, 20);
define REGION_APAC = ({}, 30);

# Bogon prefixes (IPv4)
define BOGONS_V4 = [
    0.0.0.0/8+,          # RFC 1122 'this' network
    10.0.0.0/8+,         # RFC 1918 private
    100.64.0.0/10+,      # RFC 6598 CGN
    127.0.0.0/8+,        # RFC 1122 loopback
    169.254.0.0/16+,     # RFC 3927 link-local
    172.16.0.0/12+,      # RFC 1918 private
    192.0.0.0/24+,       # RFC 6890 IETF protocol
    192.0.2.0/24+,       # RFC 5737 TEST-NET-1
    192.168.0.0/16+,     # RFC 1918 private
    198.18.0.0/15+,      # RFC 2544 benchmark
    198.51.100.0/24+,    # RFC 5737 TEST-NET-2
    203.0.113.0/24+,     # RFC 5737 TEST-NET-3
    224.0.0.0/4+,        # RFC 5771 multicast
    240.0.0.0/4+         # RFC 1112 reserved
];

# Bogon ASNs
define BOGON_ASNS = [
    0,                    # Reserved
    23456,                # AS_TRANS
    64496..64511,         # Documentation
    64512..65534,         # Private use
    65535,                # Reserved
    65536..65551,         # Documentation
    65552..131071,        # Reserved
    4200000000..4294967294, # Private use (32-bit)
    4294967295            # Reserved
];

"#, 
            self.local_asn, 
            self.router_id,
            v4_prefixes,
            v6_prefixes,
            self.local_asn, self.local_asn, self.local_asn, 
            self.local_asn, self.local_asn, self.local_asn,
            self.local_asn, self.local_asn, self.local_asn
        )
    }

    /// Generate protocol configurations
    fn generate_protocols(&self) -> String {
        format!(r#"################################################################################
# Protocol Configurations
################################################################################

# Device protocol - interface scanning
protocol device {{
    scan time 10;
}}

# Direct protocol - connected routes
protocol direct {{
    ipv4;
    ipv6;
    interface "lo";
    interface "vpp*";
}}

# Kernel protocol - sync with OS routing table
protocol kernel kernel4 {{
    ipv4 {{
        export filter {{
            if source = RTS_BGP then accept;
            if source = RTS_STATIC then accept;
            reject;
        }};
        import none;
    }};
    learn;
    persist;
    graceful restart;
}}

protocol kernel kernel6 {{
    ipv6 {{
        export filter {{
            if source = RTS_BGP then accept;
            if source = RTS_STATIC then accept;
            reject;
        }};
        import none;
    }};
    learn;
    persist;
    graceful restart;
}}

# Static routes for our prefixes
protocol static static4 {{
    ipv4;
    route 203.0.113.0/24 reject;  # Placeholder - replace with real prefixes
}}

protocol static static6 {{
    ipv6;
    route 2001:db8::/48 reject;   # Placeholder - replace with real prefixes
}}

# BFD for fast failover
protocol bfd {{
    interface "vpp*" {{
        min rx interval 100 ms;
        min tx interval 100 ms;
        idle tx interval 500 ms;
        multiplier 3;
    }};
}}

# RPKI for route validation
protocol rpki rpki1 {{
    roa4 {{ table roa4; }};
    roa6 {{ table roa6; }};
    remote "rpki.cloudflare.com" port 8282;
    retry keep 90;
    refresh keep 900;
    expire keep 172800;
}}

"#)
    }

    /// Generate filter functions
    fn generate_filters(&self) -> String {
        format!(r#"################################################################################
# Filter Functions
################################################################################

# Check for bogon prefixes
function is_bogon_prefix() {{
    if net ~ BOGONS_V4 then return true;
    return false;
}}

# Check for bogon ASN in path
function has_bogon_asn() {{
    if bgp_path ~ BOGON_ASNS then return true;
    return false;
}}

# Check RPKI status
function is_rpki_valid() {{
    if roa_check(roa4, net, bgp_path.last) = ROA_VALID then return true;
    return false;
}}

function is_rpki_invalid() {{
    if roa_check(roa4, net, bgp_path.last) = ROA_INVALID then return true;
    return false;
}}

# Standard IXP import filter
filter ixp_import {{
    # Reject bogons
    if is_bogon_prefix() then reject;
    
    # Reject bogon ASNs in path
    if has_bogon_asn() then reject;
    
    # Reject too specific prefixes
    if net.len > 24 then reject;
    
    # Reject too long AS paths
    if bgp_path.len > 64 then reject;
    
    # Reject RPKI invalid
    if is_rpki_invalid() then {{
        print "RPKI invalid: ", net, " from ", bgp_path.first;
        reject;
    }}
    
    # Set community and local preference
    bgp_community.add(IXP_LEARNED);
    bgp_local_pref = 150;
    
    # Boost RPKI valid routes
    if is_rpki_valid() then bgp_local_pref = 160;
    
    accept;
}}

# Standard IXP export filter
filter ixp_export {{
    # Only export our prefixes
    if net ~ MY_PREFIXES_V4 then accept;
    
    # Export static routes
    if source = RTS_STATIC then accept;
    
    # Export customer routes
    if (IXP_LEARNED, CUSTOMER_LEARNED) ~ bgp_community then accept;
    
    # Check no-export communities
    if NO_EXPORT_PEERS ~ bgp_community then reject;
    
    reject;
}}

# Transit import filter (lower preference)
filter transit_import {{
    if is_bogon_prefix() then reject;
    if has_bogon_asn() then reject;
    if net.len > 24 then reject;
    if bgp_path.len > 100 then reject;
    if is_rpki_invalid() then reject;
    
    bgp_community.add(TRANSIT_LEARNED);
    bgp_local_pref = 100;  # Lower than IXP
    
    if is_rpki_valid() then bgp_local_pref = 110;
    
    accept;
}}

# Transit export filter
filter transit_export {{
    if net ~ MY_PREFIXES_V4 then accept;
    if source = RTS_STATIC then accept;
    if CUSTOMER_LEARNED ~ bgp_community then accept;
    if NO_EXPORT_TRANSIT ~ bgp_community then reject;
    
    reject;
}}

# Customer import filter
filter customer_import {{
    if is_bogon_prefix() then reject;
    if net.len > 24 then reject;
    
    bgp_community.add(CUSTOMER_LEARNED);
    bgp_local_pref = 200;  # Highest preference
    
    accept;
}}

"#)
    }

    /// Generate BGP templates
    fn generate_templates(&self) -> String {
        format!(r#"################################################################################
# BGP Templates
################################################################################

# Template for IXP route servers
template bgp tpl_ixp_rs {{
    local as MY_AS;
    graceful restart on;
    long lived graceful restart on;
    
    ipv4 {{
        import filter ixp_import;
        export filter ixp_export;
        import limit 250000 action restart;
        receive limit 300000 action disable;
    }};
    
    ipv6 {{
        import filter ixp_import;
        export filter ixp_export;
        import limit 100000 action restart;
    }};
}}

# Template for bilateral peers
template bgp tpl_bilateral {{
    local as MY_AS;
    graceful restart on;
    
    ipv4 {{
        import filter ixp_import;
        export filter ixp_export;
        import limit 50000 action restart;
    }};
    
    ipv6 {{
        import filter ixp_import;
        export filter ixp_export;
        import limit 20000 action restart;
    }};
}}

# Template for transit providers
template bgp tpl_transit {{
    local as MY_AS;
    graceful restart on;
    default bgp_local_pref 100;
    
    ipv4 {{
        import filter transit_import;
        export filter transit_export;
        import limit 900000 action restart;  # Full table
    }};
    
    ipv6 {{
        import filter transit_import;
        export filter transit_export;
        import limit 200000 action restart;
    }};
}}

# Template for customers
template bgp tpl_customer {{
    local as MY_AS;
    graceful restart on;
    
    ipv4 {{
        import filter customer_import;
        export all;
        import limit 100 action restart;
    }};
}}

"#)
    }

    /// Generate IXP-specific sessions
    fn generate_ixp_sessions(&self) -> String {
        let mut sessions = String::new();
        sessions.push_str("################################################################################\n");
        sessions.push_str("# IXP Sessions\n");
        sessions.push_str("################################################################################\n\n");

        // Example sessions - would be generated from actual data
        sessions.push_str(r#"# DE-CIX Frankfurt Route Servers
protocol bgp rs_decix_1 from tpl_ixp_rs {
    neighbor 80.81.192.157 as 6695;
    description "DE-CIX RS1";
}

protocol bgp rs_decix_2 from tpl_ixp_rs {
    neighbor 80.81.192.158 as 6695;
    description "DE-CIX RS2";
}

# AMS-IX Route Servers
protocol bgp rs_amsix_1 from tpl_ixp_rs {
    neighbor 80.249.208.31 as 6777;
    description "AMS-IX RS1";
}

protocol bgp rs_amsix_2 from tpl_ixp_rs {
    neighbor 80.249.208.32 as 6777;
    description "AMS-IX RS2";
}

# LINX LON1 Route Servers
protocol bgp rs_linx_1 from tpl_ixp_rs {
    neighbor 195.66.224.1 as 8714;
    description "LINX RS1";
}

# Priority Bilateral Peers
protocol bgp peer_cloudflare from tpl_bilateral {
    neighbor 80.81.193.13 as 13335;
    description "Cloudflare (bilateral)";
}

protocol bgp peer_google from tpl_bilateral {
    neighbor 80.81.193.15 as 15169;
    description "Google (bilateral)";
}

"#);

        sessions
    }
}

/// Generate standalone BIRD config file
pub fn generate_bird_config_file(router_id: &str) -> String {
    let config = Bird2Config::new(
        router_id.parse().unwrap_or("10.255.0.1".parse().unwrap()),
        vec!["203.0.113.0/24".to_string()],
        vec!["2001:db8::/48".to_string()],
    );
    config.generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bird_config_generation() {
        let config = Bird2Config::new(
            "10.0.0.1".parse().unwrap(),
            vec!["203.0.113.0/24".to_string()],
            vec!["2001:db8::/48".to_string()],
        );
        
        let output = config.generate();
        
        assert!(output.contains("router id 10.0.0.1"));
        assert!(output.contains(&format!("define MY_AS = {}", OPENSASE_ASN)));
        assert!(output.contains("filter ixp_import"));
        assert!(output.contains("protocol rpki"));
    }

    #[test]
    fn test_standalone_generation() {
        let config = generate_bird_config_file("10.255.0.1");
        assert!(config.contains("OpenSASE Peering Engine"));
    }
}
