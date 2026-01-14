//! OpenSASE Private Backbone - Orchestrator
//!
//! Manages private backbone links between PoPs using
//! Megaport and PacketFabric APIs.

use crate::{BackboneLink, BackboneProvider, VxcStatus, PopTier, OptimizationMode};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Backbone orchestrator errors
#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("Provider API error: {0}")]
    ProviderApi(String),
    #[error("No available path between {0} and {1}")]
    NoPath(String, String),
    #[error("Insufficient budget: need ${0}, have ${1}")]
    InsufficientBudget(Decimal, Decimal),
    #[error("Link not found: {0}")]
    LinkNotFound(String),
}

pub type Result<T> = std::result::Result<T, OrchestratorError>;

/// PoP information for topology planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopInfo {
    pub id: String,
    pub datacenter: String,
    pub tier: PopTier,
    pub megaport_port_id: Option<String>,
    pub pf_port_id: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}

/// Backbone topology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackboneTopology {
    pub links: Vec<BackboneLink>,
    pub hub_pops: Vec<String>,
    pub total_bandwidth_gbps: u32,
    pub monthly_cost: Decimal,
}

/// Traffic classification for routing decisions
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TrafficClass {
    /// Voice, video - latency-sensitive
    VoiceVideo,
    /// Interactive applications
    Interactive,
    /// Bulk transfers
    Bulk,
}

/// Path selection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathSelection {
    Backbone(Option<Vec<String>>),
    Internet,
}

/// Link status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LinkStatus {
    Active,
    Degraded,
    Down,
    Provisioning,
}

/// Manages private backbone links between PoPs
pub struct BackboneOrchestrator {
    megaport_api_key: String,
    packetfabric_api_key: String,
    topology: BackboneTopology,
    pops: HashMap<String, PopInfo>,
    optimization_mode: OptimizationMode,
}

impl BackboneOrchestrator {
    /// Create a new orchestrator
    pub fn new(
        megaport_api_key: String,
        packetfabric_api_key: String,
        optimization_mode: OptimizationMode,
    ) -> Self {
        Self {
            megaport_api_key,
            packetfabric_api_key,
            topology: BackboneTopology {
                links: Vec::new(),
                hub_pops: Vec::new(),
                total_bandwidth_gbps: 0,
                monthly_cost: Decimal::ZERO,
            },
            pops: HashMap::new(),
            optimization_mode,
        }
    }

    /// Build optimal backbone topology based on PoP locations
    pub async fn build_topology(&mut self, pops: &[PopInfo]) -> Result<BackboneTopology> {
        // Store PoPs
        for pop in pops {
            self.pops.insert(pop.id.clone(), pop.clone());
        }

        let mut links = Vec::new();

        // 1. Identify hub PoPs (Tier1, largest, best connected)
        let hubs = self.identify_hubs(pops);
        self.topology.hub_pops = hubs.clone();

        // 2. Connect all PoPs to nearest hub
        for pop in pops {
            if !hubs.contains(&pop.id) {
                if let Some(nearest_hub) = self.find_nearest_hub(pop, &hubs) {
                    let link = self.create_link(pop, &self.pops[&nearest_hub].clone()).await?;
                    links.push(link);
                }
            }
        }

        // 3. Create hub mesh (all hubs connected to each other)
        for i in 0..hubs.len() {
            for j in (i + 1)..hubs.len() {
                let pop_a = &self.pops[&hubs[i]].clone();
                let pop_b = &self.pops[&hubs[j]].clone();
                let link = self.create_link(pop_a, pop_b).await?;
                links.push(link);
            }
        }

        // 4. Add redundant links for core PoPs (HA)
        for pop in pops {
            if pop.tier == PopTier::Tier1 && !hubs.contains(&pop.id) {
                if let Some(secondary_hub) = self.find_secondary_hub(pop, &hubs) {
                    let hub_pop = &self.pops[&secondary_hub].clone();
                    let link = self.create_link(pop, hub_pop).await?;
                    links.push(link);
                }
            }
        }

        // Calculate totals
        let total_bandwidth: u32 = links.iter().map(|l| l.bandwidth_mbps).sum::<u32>() / 1000;
        let total_cost: Decimal = links.iter().map(|l| l.monthly_cost).sum();

        self.topology = BackboneTopology {
            links,
            hub_pops: hubs,
            total_bandwidth_gbps: total_bandwidth,
            monthly_cost: total_cost,
        };

        Ok(self.topology.clone())
    }

    /// Identify hub PoPs based on tier and location
    fn identify_hubs(&self, pops: &[PopInfo]) -> Vec<String> {
        pops.iter()
            .filter(|p| p.tier == PopTier::Tier1)
            .map(|p| p.id.clone())
            .collect()
    }

    /// Find nearest hub to a given PoP
    fn find_nearest_hub(&self, pop: &PopInfo, hubs: &[String]) -> Option<String> {
        hubs.iter()
            .min_by(|a, b| {
                let dist_a = self.calculate_distance(pop, &self.pops[*a]);
                let dist_b = self.calculate_distance(pop, &self.pops[*b]);
                dist_a.partial_cmp(&dist_b).unwrap()
            })
            .cloned()
    }

    /// Find secondary hub (for redundancy)
    fn find_secondary_hub(&self, pop: &PopInfo, hubs: &[String]) -> Option<String> {
        let primary = self.find_nearest_hub(pop, hubs)?;
        hubs.iter()
            .filter(|h| **h != primary)
            .min_by(|a, b| {
                let dist_a = self.calculate_distance(pop, &self.pops[*a]);
                let dist_b = self.calculate_distance(pop, &self.pops[*b]);
                dist_a.partial_cmp(&dist_b).unwrap()
            })
            .cloned()
    }

    /// Calculate distance between two PoPs
    fn calculate_distance(&self, pop_a: &PopInfo, pop_b: &PopInfo) -> f64 {
        let lat1 = pop_a.latitude.to_radians();
        let lat2 = pop_b.latitude.to_radians();
        let dlat = (pop_b.latitude - pop_a.latitude).to_radians();
        let dlon = (pop_b.longitude - pop_a.longitude).to_radians();

        let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        6371.0 * c // Earth radius in km
    }

    /// Create a backbone link between two PoPs
    async fn create_link(&self, pop_a: &PopInfo, pop_b: &PopInfo) -> Result<BackboneLink> {
        // Determine provider based on availability and cost
        let provider = self.select_provider(pop_a, pop_b).await?;

        // Calculate bandwidth based on optimization mode
        let bandwidth = match self.optimization_mode {
            OptimizationMode::Performance => 10000, // 10 Gbps
            OptimizationMode::Balanced => 5000,     // 5 Gbps
            OptimizationMode::Cost => 1000,         // 1 Gbps
        };

        // Calculate cost
        let cost = self.calculate_link_cost(provider, &pop_a.datacenter, &pop_b.datacenter, bandwidth);

        Ok(BackboneLink {
            id: format!("{}-{}-{:?}", pop_a.id, pop_b.id, provider).to_lowercase(),
            name: format!("OSPB-{}-{}", pop_a.id, pop_b.id),
            provider,
            a_end: crate::VxcEndpoint {
                port_id: pop_a.megaport_port_id.clone().unwrap_or_default(),
                pop_name: pop_a.id.clone(),
                vlan_id: 100,
            },
            z_end: crate::VxcEndpoint {
                port_id: pop_b.megaport_port_id.clone().unwrap_or_default(),
                pop_name: pop_b.id.clone(),
                vlan_id: 100,
            },
            bandwidth_mbps: bandwidth,
            burst_mbps: Some(bandwidth * 2),
            status: VxcStatus::Active,
            latency_ms: Some(self.estimate_latency(pop_a, pop_b)),
            monthly_cost: cost,
        })
    }

    /// Select provider based on availability and cost
    async fn select_provider(&self, pop_a: &PopInfo, pop_b: &PopInfo) -> Result<BackboneProvider> {
        let has_megaport = pop_a.megaport_port_id.is_some() && pop_b.megaport_port_id.is_some();
        let has_pf = pop_a.pf_port_id.is_some() && pop_b.pf_port_id.is_some();

        if has_megaport && has_pf {
            // Choose based on cost
            let mp_cost = self.calculate_link_cost(BackboneProvider::Megaport, &pop_a.datacenter, &pop_b.datacenter, 1000);
            let pf_cost = self.calculate_link_cost(BackboneProvider::PacketFabric, &pop_a.datacenter, &pop_b.datacenter, 1000);
            
            if pf_cost < mp_cost {
                Ok(BackboneProvider::PacketFabric)
            } else {
                Ok(BackboneProvider::Megaport)
            }
        } else if has_megaport {
            Ok(BackboneProvider::Megaport)
        } else if has_pf {
            Ok(BackboneProvider::PacketFabric)
        } else {
            Err(OrchestratorError::NoPath(pop_a.id.clone(), pop_b.id.clone()))
        }
    }

    /// Calculate link cost
    fn calculate_link_cost(&self, provider: BackboneProvider, _dc_a: &str, _dc_b: &str, bandwidth_mbps: u32) -> Decimal {
        let cost_per_mbps = match provider {
            BackboneProvider::Megaport => Decimal::new(10, 2),      // $0.10
            BackboneProvider::PacketFabric => Decimal::new(8, 2),  // $0.08
        };
        cost_per_mbps * Decimal::from(bandwidth_mbps)
    }

    /// Estimate latency between PoPs
    fn estimate_latency(&self, pop_a: &PopInfo, pop_b: &PopInfo) -> f32 {
        let distance = self.calculate_distance(pop_a, pop_b);
        // Light in fiber: ~200km/ms
        (distance / 200.0) as f32
    }

    /// Route traffic via backbone or internet based on policy
    pub fn select_path(&self, src_pop: &str, dst_pop: &str, traffic_class: TrafficClass) -> PathSelection {
        match traffic_class {
            TrafficClass::VoiceVideo => {
                // Always use private backbone for latency-sensitive
                PathSelection::Backbone(self.find_best_path(src_pop, dst_pop))
            }
            TrafficClass::Interactive => {
                // Prefer backbone, fallback to internet
                if let Some(path) = self.find_best_path(src_pop, dst_pop) {
                    PathSelection::Backbone(Some(path))
                } else {
                    PathSelection::Internet
                }
            }
            TrafficClass::Bulk => {
                // Use cheapest path
                PathSelection::Internet
            }
        }
    }

    /// Find best path between PoPs
    fn find_best_path(&self, src: &str, dst: &str) -> Option<Vec<String>> {
        // Direct link
        for link in &self.topology.links {
            if (link.a_end.pop_name == src && link.z_end.pop_name == dst)
                || (link.a_end.pop_name == dst && link.z_end.pop_name == src)
            {
                return Some(vec![link.id.clone()]);
            }
        }

        // Via hub
        for hub in &self.topology.hub_pops {
            let to_hub = self.find_direct_link(src, hub);
            let from_hub = self.find_direct_link(hub, dst);
            if let (Some(l1), Some(l2)) = (to_hub, from_hub) {
                return Some(vec![l1, l2]);
            }
        }

        None
    }

    /// Find direct link between two PoPs
    fn find_direct_link(&self, src: &str, dst: &str) -> Option<String> {
        self.topology.links.iter().find(|l| {
            (l.a_end.pop_name == src && l.z_end.pop_name == dst)
                || (l.a_end.pop_name == dst && l.z_end.pop_name == src)
        }).map(|l| l.id.clone())
    }

    /// Get current topology
    pub fn topology(&self) -> &BackboneTopology {
        &self.topology
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distance_calculation() {
        let orchestrator = BackboneOrchestrator::new(
            String::new(),
            String::new(),
            OptimizationMode::Balanced,
        );

        let nyc = PopInfo {
            id: "nyc".to_string(),
            datacenter: "Equinix NY5".to_string(),
            tier: PopTier::Tier1,
            megaport_port_id: Some("mp-nyc".to_string()),
            pf_port_id: Some("pf-nyc".to_string()),
            latitude: 40.7128,
            longitude: -74.0060,
        };

        let lon = PopInfo {
            id: "lon".to_string(),
            datacenter: "Equinix LD5".to_string(),
            tier: PopTier::Tier1,
            megaport_port_id: Some("mp-lon".to_string()),
            pf_port_id: Some("pf-lon".to_string()),
            latitude: 51.5074,
            longitude: -0.1278,
        };

        let distance = orchestrator.calculate_distance(&nyc, &lon);
        assert!(distance > 5500.0 && distance < 5600.0); // ~5,570 km
    }

    #[test]
    fn test_path_selection() {
        let mut orchestrator = BackboneOrchestrator::new(
            String::new(),
            String::new(),
            OptimizationMode::Balanced,
        );

        // Add a link
        orchestrator.topology.links.push(BackboneLink {
            id: "nyc-lon".to_string(),
            name: "OSPB-nyc-lon".to_string(),
            provider: BackboneProvider::Megaport,
            a_end: crate::VxcEndpoint {
                port_id: "mp-nyc".to_string(),
                pop_name: "nyc".to_string(),
                vlan_id: 100,
            },
            z_end: crate::VxcEndpoint {
                port_id: "mp-lon".to_string(),
                pop_name: "lon".to_string(),
                vlan_id: 100,
            },
            bandwidth_mbps: 10000,
            burst_mbps: Some(20000),
            status: VxcStatus::Active,
            latency_ms: Some(35.0),
            monthly_cost: Decimal::from(1000),
        });

        // VoiceVideo should use backbone
        let path = orchestrator.select_path("nyc", "lon", TrafficClass::VoiceVideo);
        assert!(matches!(path, PathSelection::Backbone(Some(_))));

        // Bulk can use internet
        let path = orchestrator.select_path("nyc", "lon", TrafficClass::Bulk);
        assert!(matches!(path, PathSelection::Internet));
    }
}
