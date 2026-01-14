//! RIR Resource Management
//!
//! Guide and tracking for AS number and IP space acquisition
//! from Regional Internet Registries.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Regional Internet Registry
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Rir {
    /// RIPE NCC - Europe, Middle East, Central Asia
    Ripe,
    /// ARIN - North America, Caribbean
    Arin,
    /// APNIC - Asia Pacific
    Apnic,
    /// LACNIC - Latin America, Caribbean
    Lacnic,
    /// AFRINIC - Africa
    Afrinic,
}

impl Rir {
    /// Get RIR website
    pub fn website(&self) -> &'static str {
        match self {
            Rir::Ripe => "https://www.ripe.net",
            Rir::Arin => "https://www.arin.net",
            Rir::Apnic => "https://www.apnic.net",
            Rir::Lacnic => "https://www.lacnic.net",
            Rir::Afrinic => "https://www.afrinic.net",
        }
    }

    /// Get RIR for a region
    pub fn for_region(region: &str) -> Self {
        match region {
            "europe" | "eu" | "middle-east" => Rir::Ripe,
            "north-america" | "na" | "us" | "canada" => Rir::Arin,
            "asia-pacific" | "apac" | "asia" => Rir::Apnic,
            "latin-america" | "latam" | "south-america" => Rir::Lacnic,
            "africa" => Rir::Afrinic,
            _ => Rir::Ripe, // Default
        }
    }
}

/// RIR resource allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RirResources {
    pub asn: Option<u32>,
    pub ipv4_prefixes: Vec<String>,
    pub ipv6_prefixes: Vec<String>,
    pub rir: Rir,
    pub membership_type: String,
    pub annual_cost: f64,
    pub currency: String,
}

/// RIR pricing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RirPricing {
    pub rir: Rir,
    pub asn_cost: f64,
    pub asn_annual: f64,
    pub ipv6_48_cost: f64,
    pub membership_min: f64,
    pub currency: String,
    pub timeline_weeks: (u32, u32),
    pub notes: String,
}

/// Get pricing for all RIRs
pub fn get_rir_pricing() -> Vec<RirPricing> {
    vec![
        RirPricing {
            rir: Rir::Ripe,
            asn_cost: 0.0,
            asn_annual: 50.0,
            ipv6_48_cost: 0.0,
            membership_min: 1400.0,
            currency: "EUR".to_string(),
            timeline_weeks: (2, 4),
            notes: "IPv4 waitlist, transfer market $20-40K for /24".to_string(),
        },
        RirPricing {
            rir: Rir::Arin,
            asn_cost: 500.0,
            asn_annual: 100.0,
            ipv6_48_cost: 250.0,
            membership_min: 0.0,
            currency: "USD".to_string(),
            timeline_weeks: (1, 2),
            notes: "IPv4 waitlist, transfer market $25-50K for /24".to_string(),
        },
        RirPricing {
            rir: Rir::Apnic,
            asn_cost: 0.0,
            asn_annual: 0.0,
            ipv6_48_cost: 0.0,
            membership_min: 1500.0,
            currency: "USD".to_string(),
            timeline_weeks: (2, 3),
            notes: "ASN and IPv6 included with membership".to_string(),
        },
        RirPricing {
            rir: Rir::Lacnic,
            asn_cost: 0.0,
            asn_annual: 0.0,
            ipv6_48_cost: 0.0,
            membership_min: 500.0,
            currency: "USD".to_string(),
            timeline_weeks: (2, 4),
            notes: "Resources included with membership".to_string(),
        },
        RirPricing {
            rir: Rir::Afrinic,
            asn_cost: 0.0,
            asn_annual: 0.0,
            ipv6_48_cost: 0.0,
            membership_min: 250.0,
            currency: "USD".to_string(),
            timeline_weeks: (2, 4),
            notes: "Resources included with membership".to_string(),
        },
    ]
}

/// IPv4 broker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Broker {
    pub name: &'static str,
    pub website: &'static str,
    pub price_range_per_24: (u32, u32),
    pub timeline_weeks: (u32, u32),
}

/// Get IPv4 brokers
pub fn get_ipv4_brokers() -> Vec<Ipv4Broker> {
    vec![
        Ipv4Broker {
            name: "IPv4.Global (Hilco Streambank)",
            website: "https://ipv4.global",
            price_range_per_24: (20000, 35000),
            timeline_weeks: (1, 2),
        },
        Ipv4Broker {
            name: "Brander Group",
            website: "https://brandergroup.net",
            price_range_per_24: (22000, 40000),
            timeline_weeks: (1, 3),
        },
        Ipv4Broker {
            name: "IPTrading",
            website: "https://www.iptrading.com",
            price_range_per_24: (20000, 38000),
            timeline_weeks: (1, 2),
        },
        Ipv4Broker {
            name: "Prefixx",
            website: "https://prefixx.net",
            price_range_per_24: (18000, 35000),
            timeline_weeks: (2, 4),
        },
    ]
}

/// Temporary IP solutions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporaryIpSolution {
    pub provider: &'static str,
    pub allocation: &'static str,
    pub monthly_cost: f64,
    pub can_announce_bgp: bool,
    pub notes: &'static str,
}

/// Get temporary IP solutions
pub fn get_temporary_solutions() -> Vec<TemporaryIpSolution> {
    vec![
        TemporaryIpSolution {
            provider: "Equinix Metal",
            allocation: "/29 - /28",
            monthly_cost: 0.0,
            can_announce_bgp: true,
            notes: "BGP included, can bring own IPs later",
        },
        TemporaryIpSolution {
            provider: "Vultr",
            allocation: "/29",
            monthly_cost: 0.0,
            can_announce_bgp: true,
            notes: "BGP available on bare metal",
        },
        TemporaryIpSolution {
            provider: "Hetzner",
            allocation: "/29",
            monthly_cost: 3.0,
            can_announce_bgp: false,
            notes: "No BGP, but cheap failover IPs",
        },
        TemporaryIpSolution {
            provider: "OVH Cloud",
            allocation: "/28",
            monthly_cost: 10.0,
            can_announce_bgp: false,
            notes: "IP failover available",
        },
    ]
}

/// Generate acquisition guide
pub fn acquisition_guide() -> String {
    r#"
=== AS Number & IP Space Acquisition Guide ===

1. RIPE NCC (Europe, Middle East, Central Asia)
   - AS Number: €50/year
   - IPv4 /24: Waitlist (transfer market: €20-40K)
   - IPv6 /48: Free with membership
   - Membership: €1,400/year (minimum)
   - Timeline: 2-4 weeks
   - URL: https://www.ripe.net/membership
   - IRR: RIPE-NONAUTH or RADB

2. ARIN (North America, Caribbean)
   - AS Number: $500 one-time + $100/year
   - IPv4 /24: Waitlist (transfer market: $25-50K)
   - IPv6 /48: $250/year
   - Timeline: 1-2 weeks
   - URL: https://www.arin.net
   - IRR: ARIN IRR

3. APNIC (Asia Pacific)
   - AS Number: Included with membership
   - IPv4: Transfer market only
   - IPv6 /48: Included
   - Membership: $1,500-5,000/year
   - URL: https://www.apnic.net
   - IRR: RADB or APNIC

4. LACNIC (Latin America, Caribbean)
   - Resources: Included with membership
   - Membership: $500-2,000/year
   - URL: https://www.lacnic.net

5. AFRINIC (Africa)
   - Resources: Included with membership  
   - Membership: $250-1,000/year
   - URL: https://www.afrinic.net

=== IPv4 Acquisition Alternatives ===

1. IP Broker Purchase
   - Buy IPv4 /24 from broker: $20-50K
   - Providers: IPv4.Global, Brander Group, IPTrading
   - Timeline: 1-2 weeks
   - Includes RIR transfer assistance

2. Lease IPv4 Space
   - Monthly lease: $0.50-1.00 per IP
   - /24 lease: $128-256/month
   - No upfront cost
   - Providers: IPXO, Heficed

3. Provider Allocation (Temporary)
   - Equinix Metal: /29 included, BGP support
   - Vultr: /29 included, BGP on bare metal
   - Announce via provider ASN initially
   - Upgrade to own ASN later

=== Recommended Approach for OpenSASE ===

Phase 1: Bootstrap (Week 1-2)
- Use Equinix Metal IPs with their ASN
- Establish presence at first IXP

Phase 2: Own Resources (Week 3-6)
- Apply for RIPE membership + ASN
- Purchase IPv4 /24 from broker
- Request IPv6 /48 from RIPE

Phase 3: Global Expansion (Month 2+)
- Apply for ARIN and APNIC resources
- Transfer existing prefixes if needed
- Establish IRR entries in all regions
"#.to_string()
}

/// IRR (Internet Routing Registry) entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrrEntry {
    pub registry: String,
    pub as_set: String,
    pub route_objects: Vec<String>,
    pub maintainer: String,
}

impl IrrEntry {
    /// Generate RPSL for route object
    pub fn generate_route_object(prefix: &str, asn: u32, maintainer: &str) -> String {
        format!(r#"route:          {}
descr:          OpenSASE Network
origin:         AS{}
mnt-by:         {}
source:         RIPE
"#, prefix, asn, maintainer)
    }

    /// Generate AS-SET object
    pub fn generate_as_set(name: &str, asn: u32, maintainer: &str) -> String {
        format!(r#"as-set:         {}
descr:          OpenSASE AS-SET
members:        AS{}
tech-c:         OSPE-RIPE
admin-c:        OSPE-RIPE
mnt-by:         {}
source:         RIPE
"#, name, asn, maintainer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rir_for_region() {
        assert_eq!(Rir::for_region("europe"), Rir::Ripe);
        assert_eq!(Rir::for_region("us"), Rir::Arin);
        assert_eq!(Rir::for_region("asia"), Rir::Apnic);
    }

    #[test]
    fn test_pricing() {
        let pricing = get_rir_pricing();
        assert_eq!(pricing.len(), 5);
        
        let ripe = pricing.iter().find(|p| p.rir == Rir::Ripe).unwrap();
        assert_eq!(ripe.currency, "EUR");
    }

    #[test]
    fn test_route_object_generation() {
        let route = IrrEntry::generate_route_object("203.0.113.0/24", 65100, "MNT-OPENSASE");
        assert!(route.contains("origin:         AS65100"));
    }
}
