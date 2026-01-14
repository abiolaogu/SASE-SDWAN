//! PeeringDB API Integration
//!
//! Fetches IXP, network, and peering information from PeeringDB.

use crate::{InternetExchange, PeerNetwork, PeeringPolicy, NetworkType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// PeeringDB API base URL
pub const PEERINGDB_API: &str = "https://www.peeringdb.com/api";

/// PeeringDB errors
#[derive(Debug, Error)]
pub enum PeeringDbError {
    #[error("API request failed: {0}")]
    Request(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Rate limited")]
    RateLimited,
    #[error("Not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, PeeringDbError>;

/// PeeringDB API response wrapper
#[derive(Debug, Deserialize)]
struct PeeringDbResponse<T> {
    data: Vec<T>,
}

/// IXP from PeeringDB
#[derive(Debug, Clone, Deserialize)]
pub struct PdbIxp {
    pub id: u32,
    pub name: String,
    pub name_long: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub region_continent: Option<String>,
    pub website: Option<String>,
    pub policy_general: Option<String>,
    pub net_count: u32,
    pub proto_unicast: bool,
    pub proto_multicast: bool,
}

/// Network from PeeringDB
#[derive(Debug, Clone, Deserialize)]
pub struct PdbNetwork {
    pub id: u32,
    pub asn: u32,
    pub name: String,
    pub aka: Option<String>,
    pub irr_as_set: Option<String>,
    pub website: Option<String>,
    pub looking_glass: Option<String>,
    pub policy_general: Option<String>,
    pub info_prefixes4: Option<u32>,
    pub info_prefixes6: Option<u32>,
    pub info_ratio: Option<String>,
    pub info_type: Option<String>,
}

/// Network-IXP connection from PeeringDB
#[derive(Debug, Clone, Deserialize)]
pub struct PdbNetIxlan {
    pub id: u32,
    pub net_id: u32,
    pub asn: u32,
    pub name: String,
    pub ixlan_id: u32,
    pub ix_id: u32,
    pub ipaddr4: Option<String>,
    pub ipaddr6: Option<String>,
    pub speed: u32,
    pub is_rs_peer: bool,
}

/// IXP prefix information
#[derive(Debug, Clone, Deserialize)]
pub struct PdbIxpPrefix {
    pub id: u32,
    pub ixlan_id: u32,
    pub protocol: String,
    pub prefix: String,
}

/// PeeringDB client
pub struct PeeringDbClient {
    api_key: Option<String>,
    cache: HashMap<String, String>,
}

impl PeeringDbClient {
    /// Create new PeeringDB client
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            cache: HashMap::new(),
        }
    }

    /// Get IXP by ID
    pub async fn get_ixp(&self, ixp_id: u32) -> Result<InternetExchange> {
        let data = self.fetch::<PdbIxp>(&format!("ix/{}", ixp_id)).await?;
        Ok(self.convert_ixp(&data))
    }

    /// Search IXPs by city/country
    pub async fn search_ixps(&self, query: &str) -> Result<Vec<InternetExchange>> {
        let data = self.fetch_list::<PdbIxp>(&format!("ix?name__contains={}", query)).await?;
        Ok(data.iter().map(|i| self.convert_ixp(i)).collect())
    }

    /// Get IXPs by country
    pub async fn get_ixps_by_country(&self, country_code: &str) -> Result<Vec<InternetExchange>> {
        let data = self.fetch_list::<PdbIxp>(&format!("ix?country={}", country_code)).await?;
        Ok(data.iter().map(|i| self.convert_ixp(i)).collect())
    }

    /// Get network by ASN
    pub async fn get_network(&self, asn: u32) -> Result<PeerNetwork> {
        let data = self.fetch_list::<PdbNetwork>(&format!("net?asn={}", asn)).await?;
        data.first()
            .map(|n| self.convert_network(n))
            .ok_or_else(|| PeeringDbError::NotFound(format!("ASN {}", asn)))
    }

    /// Get networks at an IXP
    pub async fn get_ixp_members(&self, ixp_id: u32) -> Result<Vec<PdbNetIxlan>> {
        self.fetch_list::<PdbNetIxlan>(&format!("netixlan?ix_id={}", ixp_id)).await
    }

    /// Get IXPs where a network is present
    pub async fn get_network_ixps(&self, asn: u32) -> Result<Vec<PdbNetIxlan>> {
        self.fetch_list::<PdbNetIxlan>(&format!("netixlan?asn={}", asn)).await
    }

    /// Get IXP LAN prefixes
    pub async fn get_ixp_prefixes(&self, ixp_id: u32) -> Result<Vec<PdbIxpPrefix>> {
        self.fetch_list::<PdbIxpPrefix>(&format!("ixpfx?ix_id={}", ixp_id)).await
    }

    /// Find common IXPs between two ASNs
    pub async fn find_common_ixps(&self, asn1: u32, asn2: u32) -> Result<Vec<u32>> {
        let ixps1 = self.get_network_ixps(asn1).await?;
        let ixps2 = self.get_network_ixps(asn2).await?;
        
        let ixp_ids1: std::collections::HashSet<u32> = ixps1.iter().map(|i| i.ix_id).collect();
        let ixp_ids2: std::collections::HashSet<u32> = ixps2.iter().map(|i| i.ix_id).collect();
        
        Ok(ixp_ids1.intersection(&ixp_ids2).copied().collect())
    }

    /// Get candidate peers at an IXP (networks with open peering policy)
    pub async fn get_candidate_peers(&self, ixp_id: u32) -> Result<Vec<PeerNetwork>> {
        let members = self.get_ixp_members(ixp_id).await?;
        let mut candidates = Vec::new();
        
        for member in members {
            if let Ok(network) = self.get_network(member.asn).await {
                if network.peering_policy == PeeringPolicy::Open {
                    candidates.push(network);
                }
            }
        }
        
        Ok(candidates)
    }

    /// Fetch single item
    async fn fetch<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<T> {
        let items = self.fetch_list::<T>(endpoint).await?;
        items.into_iter().next().ok_or_else(|| PeeringDbError::NotFound(endpoint.to_string()))
    }

    /// Fetch list of items
    async fn fetch_list<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<Vec<T>> {
        // In production, use reqwest
        // For now, return mock data structure
        tracing::info!("PeeringDB API: GET {}/{}", PEERINGDB_API, endpoint);
        
        // Placeholder - actual implementation would use HTTP client
        Ok(Vec::new())
    }

    /// Convert PDB IXP to our type
    fn convert_ixp(&self, pdb: &PdbIxp) -> InternetExchange {
        InternetExchange {
            id: pdb.id,
            name: pdb.name.clone(),
            name_long: pdb.name_long.clone().unwrap_or_default(),
            city: pdb.city.clone().unwrap_or_default(),
            country: pdb.country.clone().unwrap_or_default(),
            region: pdb.region_continent.clone().unwrap_or_default(),
            website: pdb.website.clone(),
            peering_policy: pdb.policy_general.clone().unwrap_or_else(|| "Open".to_string()),
            member_count: pdb.net_count,
            traffic_gbps: None,
            ipv4_prefix: None,
            ipv6_prefix: None,
        }
    }

    /// Convert PDB network to our type
    fn convert_network(&self, pdb: &PdbNetwork) -> PeerNetwork {
        PeerNetwork {
            asn: pdb.asn,
            name: pdb.name.clone(),
            aka: pdb.aka.clone(),
            irr_as_set: pdb.irr_as_set.clone(),
            website: pdb.website.clone(),
            looking_glass: pdb.looking_glass.clone(),
            peering_policy: match pdb.policy_general.as_deref() {
                Some("Open") => PeeringPolicy::Open,
                Some("Selective") => PeeringPolicy::Selective,
                Some("Restrictive") => PeeringPolicy::Restrictive,
                _ => PeeringPolicy::Required,
            },
            max_prefixes_v4: pdb.info_prefixes4.unwrap_or(100),
            max_prefixes_v6: pdb.info_prefixes6.unwrap_or(10),
            traffic_ratio: pdb.info_ratio.clone().unwrap_or_else(|| "Balanced".to_string()),
            info_type: match pdb.info_type.as_deref() {
                Some("ISP") => NetworkType::Isp,
                Some("NSP") => NetworkType::Nsp,
                Some("Content") => NetworkType::Content,
                Some("Enterprise") => NetworkType::Enterprise,
                Some("Cable/DSL/ISP") => NetworkType::Cable,
                Some("Educational/Research") => NetworkType::Edu,
                Some("Not Disclosed") | Some("Not For Profit") => NetworkType::NotForProfit,
                _ => NetworkType::Isp,
            },
        }
    }
}

/// Top-tier IXPs for OpenSASE presence
pub fn get_priority_ixps() -> Vec<(u32, &'static str, &'static str)> {
    vec![
        // Tier 1 - Must have
        (26, "DE-CIX Frankfurt", "DE"),
        (18, "AMS-IX", "NL"),
        (10, "LINX LON1", "GB"),
        (171, "Equinix Ashburn", "US"),
        (387, "Equinix New York", "US"),
        (64, "NL-ix", "NL"),
        (31, "France-IX Paris", "FR"),
        
        // Tier 2 - High value
        (1, "HKIX", "HK"),
        (2, "JPIX Tokyo", "JP"),
        (16, "SIX Seattle", "US"),
        (59, "Any2 Los Angeles", "US"),
        (387, "Equinix Singapore", "SG"),
        (44, "SGIX", "SG"),
        
        // Tier 3 - Regional coverage
        (342, "IX.br São Paulo", "BR"),
        (137, "MSK-IX Moscow", "RU"),
        (87, "KINX Seoul", "KR"),
        (176, "MIX Milan", "IT"),
        (48, "SwissIX", "CH"),
    ]
}

/// Get recommended IXPs for a region
pub fn get_regional_ixps(region: &str) -> Vec<(u32, &'static str)> {
    match region {
        "us-east" => vec![
            (171, "Equinix Ashburn"),
            (387, "Equinix New York"),
        ],
        "us-west" => vec![
            (59, "Any2 Los Angeles"),
            (16, "SIX Seattle"),
        ],
        "eu-west" => vec![
            (26, "DE-CIX Frankfurt"),
            (18, "AMS-IX"),
            (10, "LINX LON1"),
        ],
        "ap-southeast" => vec![
            (44, "SGIX"),
            (387, "Equinix Singapore"),
        ],
        "ap-east" => vec![
            (1, "HKIX"),
            (2, "JPIX Tokyo"),
        ],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ixps() {
        let ixps = get_priority_ixps();
        assert!(ixps.len() >= 15);
        assert!(ixps.iter().any(|(_, name, _)| name.contains("DE-CIX")));
    }

    #[test]
    fn test_regional_ixps() {
        let us_east = get_regional_ixps("us-east");
        assert!(!us_east.is_empty());
        
        let eu = get_regional_ixps("eu-west");
        assert!(eu.len() >= 3);
    }
}
