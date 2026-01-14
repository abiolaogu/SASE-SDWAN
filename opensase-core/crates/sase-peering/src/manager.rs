//! Automated Peering Manager
//!
//! Discovers candidates via PeeringDB, establishes sessions,
//! and monitors peering health.

use crate::{
    PeeringDbClient, IxpPort, PeeringSession, BgpSessionState,
    SessionManager, PeeringType, OPENSASE_ASN,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Peering candidate discovered from PeeringDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringCandidate {
    pub asn: u32,
    pub name: String,
    pub peering_policy: PeeringPolicy,
    pub network_type: NetworkType,
    pub common_ixps: Vec<String>,
    pub traffic_estimate: TrafficEstimate,
    pub priority: u32,
    pub contact_email: Option<String>,
    pub peeringdb_url: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PeeringPolicy {
    Open,
    Selective,
    Restrictive,
    RequiredNoInfo,
}

impl std::str::FromStr for PeeringPolicy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "open" => Ok(PeeringPolicy::Open),
            "selective" => Ok(PeeringPolicy::Selective),
            "restrictive" => Ok(PeeringPolicy::Restrictive),
            _ => Ok(PeeringPolicy::RequiredNoInfo),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum NetworkType {
    Nsp,           // Network Service Provider (ISP)
    Content,       // Content/CDN
    Enterprise,    // Enterprise
    Educational,   // Educational/Research
    RouteServer,   // Route server
    Other,
}

impl std::str::FromStr for NetworkType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nsp" => Ok(NetworkType::Nsp),
            "content" => Ok(NetworkType::Content),
            "enterprise" => Ok(NetworkType::Enterprise),
            "educational" => Ok(NetworkType::Educational),
            "route server" => Ok(NetworkType::RouteServer),
            _ => Ok(NetworkType::Other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEstimate {
    pub inbound_gbps: f32,
    pub outbound_gbps: f32,
    pub ratio: f32,
    pub value_score: u32,
}

/// BGP session status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub peer_asn: u32,
    pub peer_name: String,
    pub peer_ip: IpAddr,
    pub state: String,
    pub uptime_seconds: u64,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
    pub last_error: Option<String>,
    pub ixp: String,
}

/// Automated peering manager
pub struct PeeringManager {
    peeringdb: PeeringDbClient,
    our_asn: u32,
    our_ixp_ports: HashMap<String, IxpPort>,
    sessions: SessionManager,
}

impl PeeringManager {
    pub fn new(our_asn: u32) -> Self {
        Self {
            peeringdb: PeeringDbClient::new(),
            our_asn,
            our_ixp_ports: HashMap::new(),
            sessions: SessionManager::new(),
        }
    }

    /// Add an IXP port
    pub fn add_ixp_port(&mut self, port: IxpPort) {
        self.our_ixp_ports.insert(port.ixp_name.clone(), port);
    }

    /// Find potential peering candidates at our IXPs
    pub async fn find_peering_candidates(&self) -> Vec<PeeringCandidate> {
        let mut candidates = Vec::new();
        let mut seen_asns: HashMap<u32, Vec<String>> = HashMap::new();

        for (ixp_name, port) in &self.our_ixp_ports {
            // Get all networks at this IXP from PeeringDB
            let ixp_members = self.peeringdb.get_ixp_members(port.ixp_id).await
                .unwrap_or_default();

            for member in ixp_members {
                if member.asn == self.our_asn {
                    continue;
                }

                // Track which IXPs we share
                seen_asns.entry(member.asn)
                    .or_default()
                    .push(ixp_name.clone());
            }
        }

        // Build candidate list
        for (asn, ixps) in seen_asns {
            let network = match self.peeringdb.get_network(asn).await {
                Ok(n) => n,
                Err(_) => continue,
            };

            let net_type: NetworkType = network.info_type.parse().unwrap_or(NetworkType::Other);

            // Focus on ISPs and content networks
            if net_type != NetworkType::Nsp && net_type != NetworkType::Content {
                continue;
            }

            let policy: PeeringPolicy = network.policy_general.parse()
                .unwrap_or(PeeringPolicy::RequiredNoInfo);

            // Skip restrictive networks
            if policy == PeeringPolicy::Restrictive {
                continue;
            }

            let traffic = self.estimate_traffic_value(&network);
            let priority = self.calculate_priority(&network, &traffic);

            candidates.push(PeeringCandidate {
                asn,
                name: network.name.clone(),
                peering_policy: policy,
                network_type: net_type,
                common_ixps: ixps,
                traffic_estimate: traffic,
                priority,
                contact_email: network.policy_url.clone(),
                peeringdb_url: format!("https://www.peeringdb.com/asn/{}", asn),
            });
        }

        // Sort by priority (highest first)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        candidates
    }

    /// Estimate traffic value for a network
    fn estimate_traffic_value(&self, network: &crate::peeringdb::PdbNetwork) -> TrafficEstimate {
        // Estimate based on network size and type
        let base_traffic = match network.info_traffic.as_str() {
            "0-20Mbps" => 0.01,
            "20-100Mbps" => 0.05,
            "100-1000Mbps" => 0.5,
            "1-5Gbps" => 2.5,
            "5-10Gbps" => 7.5,
            "10-20Gbps" => 15.0,
            "20-50Gbps" => 35.0,
            "50-100Gbps" => 75.0,
            "100-200Gbps" => 150.0,
            "200-500Gbps" => 350.0,
            "500-1000Gbps" => 750.0,
            _ => 1.0,
        };

        // Estimate ratio
        let ratio = match network.info_ratio.as_str() {
            "Balanced" => 1.0,
            "Heavy Inbound" => 0.3,
            "Heavy Outbound" => 3.0,
            _ => 1.0,
        };

        // Content/CDN networks bring more inbound
        let type_factor = match network.info_type.as_str() {
            "Content" => 2.0,
            "NSP" => 1.5,
            _ => 1.0,
        };

        TrafficEstimate {
            inbound_gbps: (base_traffic * type_factor * 0.01) as f32,
            outbound_gbps: (base_traffic * type_factor * 0.01 * ratio) as f32,
            ratio: ratio as f32,
            value_score: (base_traffic * type_factor * 10.0) as u32,
        }
    }

    /// Calculate peering priority
    fn calculate_priority(&self, network: &crate::peeringdb::PdbNetwork, traffic: &TrafficEstimate) -> u32 {
        let mut priority = traffic.value_score;

        // Boost for open peering policy
        if network.policy_general == "Open" {
            priority += 20;
        }

        // Boost for content/CDN networks (reduce latency)
        if network.info_type == "Content" {
            priority += 30;
        }

        // Boost for large ISPs
        if network.info_type == "NSP" {
            priority += 15;
        }

        priority
    }

    /// Generate BIRD configuration for a peering session
    pub fn generate_session_config(&self, candidate: &PeeringCandidate, peer_ip: IpAddr) -> String {
        let ixp_slug = candidate.common_ixps.first()
            .map(|s| s.to_lowercase().replace("-", "_").replace(" ", "_"))
            .unwrap_or_else(|| "ixp".to_string());

        format!(r#"
# Peer: {} (AS{})
# Policy: {:?}
# PeeringDB: {}
protocol bgp as{}_{} from tpl_bilateral {{
    description "{} via {}";
    neighbor {} as {};
}}
"#,
            candidate.name, candidate.asn,
            candidate.peering_policy,
            candidate.peeringdb_url,
            candidate.asn, ixp_slug,
            candidate.name, candidate.common_ixps.join("/"),
            peer_ip, candidate.asn
        )
    }

    /// Generate peering request email
    pub fn generate_peering_request(&self, candidate: &PeeringCandidate) -> String {
        let ixp_list = candidate.common_ixps.iter()
            .map(|ixp| format!("   - {}", ixp))
            .collect::<Vec<_>>()
            .join("\n");

        format!(r#"Subject: Peering Request - AS{} (OpenSASE)

Dear {} Peering Team,

We would like to establish a peering relationship with AS{} at the following IXPs:

{}

About OpenSASE:
- ASN: {}
- Network Type: SASE/SD-WAN Provider
- Peering Policy: Open
- Traffic Type: Customer traffic, balanced ratio
- 24x7 NOC: noc@opensase.io
- PeeringDB: https://www.peeringdb.com/asn/{}

Our IXP Presence:
{}

Technical Contact:
- Email: peering@opensase.io
- Phone: +1-XXX-XXX-XXXX

We look forward to establishing a mutually beneficial peering relationship.

Best regards,
OpenSASE Peering Team
"#,
            self.our_asn,
            candidate.name, candidate.asn,
            ixp_list,
            self.our_asn, self.our_asn,
            self.our_ixp_ports.keys()
                .map(|ixp| format!("- {}", ixp))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Get high-priority CDN candidates
    pub fn get_priority_cdn_candidates() -> Vec<(u32, &'static str)> {
        vec![
            (13335, "Cloudflare"),
            (15169, "Google"),
            (32934, "Facebook/Meta"),
            (16509, "Amazon AWS"),
            (8075, "Microsoft"),
            (20940, "Akamai"),
            (2906, "Netflix"),
            (54113, "Fastly"),
            (6185, "Apple"),
            (46489, "Twitch"),
        ]
    }

    /// Get priority ISP candidates
    pub fn get_priority_isp_candidates() -> Vec<(u32, &'static str)> {
        vec![
            (3320, "Deutsche Telekom"),
            (3356, "Lumen/Level3"),
            (174, "Cogent"),
            (6939, "Hurricane Electric"),
            (1299, "Telia"),
            (3257, "GTT"),
            (7922, "Comcast"),
            (7018, "AT&T"),
            (701, "Verizon"),
            (6830, "Liberty Global"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peering_policy_parse() {
        assert_eq!("Open".parse::<PeeringPolicy>().unwrap(), PeeringPolicy::Open);
        assert_eq!("Selective".parse::<PeeringPolicy>().unwrap(), PeeringPolicy::Selective);
    }

    #[test]
    fn test_priority_cdns() {
        let cdns = PeeringManager::get_priority_cdn_candidates();
        assert_eq!(cdns.len(), 10);
        assert_eq!(cdns[0].1, "Cloudflare");
    }

    #[test]
    fn test_generate_email() {
        let manager = PeeringManager::new(65100);
        let candidate = PeeringCandidate {
            asn: 13335,
            name: "Cloudflare".to_string(),
            peering_policy: PeeringPolicy::Open,
            network_type: NetworkType::Content,
            common_ixps: vec!["DE-CIX Frankfurt".to_string()],
            traffic_estimate: TrafficEstimate {
                inbound_gbps: 1.0,
                outbound_gbps: 0.5,
                ratio: 2.0,
                value_score: 100,
            },
            priority: 150,
            contact_email: Some("peering@cloudflare.com".to_string()),
            peeringdb_url: "https://www.peeringdb.com/asn/13335".to_string(),
        };

        let email = manager.generate_peering_request(&candidate);
        assert!(email.contains("Cloudflare"));
        assert!(email.contains("AS13335"));
    }
}
