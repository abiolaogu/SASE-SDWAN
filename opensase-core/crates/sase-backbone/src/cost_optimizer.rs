//! Cost Optimizer for OSPB
//!
//! Optimizes bandwidth allocation and provider selection
//! to minimize costs while meeting latency requirements.

use crate::{BackboneLink, BackboneProvider, OptimizationMode};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Pricing information for providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPricing {
    /// Cost per Mbps per month
    pub cost_per_mbps: Decimal,
    /// Port monthly cost
    pub port_monthly: Decimal,
    /// Burst pricing (per Mbps over commit)
    pub burst_per_mbps: Option<Decimal>,
    /// Commit discount percentage
    pub commit_discount: HashMap<u32, Decimal>, // months -> discount %
}

impl Default for ProviderPricing {
    fn default() -> Self {
        Self {
            cost_per_mbps: Decimal::new(10, 2), // $0.10
            port_monthly: Decimal::from(500),
            burst_per_mbps: Some(Decimal::new(20, 2)), // $0.20
            commit_discount: HashMap::from([
                (12, Decimal::new(20, 0)),  // 20% off
                (24, Decimal::new(30, 0)),  // 30% off
                (36, Decimal::new(40, 0)),  // 40% off
            ]),
        }
    }
}

/// Bandwidth allocation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthPlan {
    pub allocations: HashMap<String, u32>, // link_id -> bandwidth_mbps
    pub total_cost: Decimal,
    pub optimization_mode: OptimizationMode,
    pub generated_at: DateTime<Utc>,
}

/// Cost report for a period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostReport {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub sections: HashMap<String, ProviderCost>,
    pub total: Decimal,
    pub recommendations: Vec<CostRecommendation>,
}

/// Provider-specific costs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCost {
    pub provider: String,
    pub port_costs: Decimal,
    pub vxc_costs: Decimal,
    pub burst_costs: Decimal,
    pub total: Decimal,
}

/// Cost optimization recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecommendation {
    pub link_id: String,
    pub recommendation: String,
    pub potential_savings: Decimal,
    pub action: RecommendedAction,
}

/// Recommended actions for cost optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendedAction {
    ScaleDown { current_mbps: u32, recommended_mbps: u32 },
    ScaleUp { current_mbps: u32, recommended_mbps: u32 },
    SwitchProvider { from: BackboneProvider, to: BackboneProvider },
    ExtendCommit { current_months: u32, recommended_months: u32 },
    RemoveLink,
}

/// Traffic demand between PoPs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficDemand {
    pub src_pop: String,
    pub dst_pop: String,
    pub bandwidth_mbps: u32,
    pub peak_mbps: u32,
    pub latency_requirement_ms: Option<f32>,
}

/// Cost optimizer for backbone
pub struct CostOptimizer {
    megaport_pricing: ProviderPricing,
    packetfabric_pricing: ProviderPricing,
    traffic_demands: Vec<TrafficDemand>,
    budget: Option<Decimal>,
}

impl CostOptimizer {
    /// Create new cost optimizer
    pub fn new() -> Self {
        Self {
            megaport_pricing: ProviderPricing {
                cost_per_mbps: Decimal::new(10, 2),
                port_monthly: Decimal::from(1500),
                burst_per_mbps: Some(Decimal::new(15, 2)),
                commit_discount: HashMap::from([
                    (12, Decimal::new(15, 0)),
                    (24, Decimal::new(25, 0)),
                    (36, Decimal::new(35, 0)),
                ]),
            },
            packetfabric_pricing: ProviderPricing {
                cost_per_mbps: Decimal::new(8, 2),
                port_monthly: Decimal::from(1200),
                burst_per_mbps: Some(Decimal::new(12, 2)),
                commit_discount: HashMap::from([
                    (12, Decimal::new(20, 0)),
                    (24, Decimal::new(30, 0)),
                    (36, Decimal::new(40, 0)),
                ]),
            },
            traffic_demands: Vec::new(),
            budget: None,
        }
    }

    /// Set monthly budget
    pub fn set_budget(&mut self, budget: Decimal) {
        self.budget = Some(budget);
    }

    /// Add traffic demand
    pub fn add_traffic_demand(&mut self, demand: TrafficDemand) {
        self.traffic_demands.push(demand);
    }

    /// Calculate optimal bandwidth allocation
    pub fn optimize_bandwidth(&self, links: &[BackboneLink], mode: OptimizationMode) -> BandwidthPlan {
        let mut allocations = HashMap::new();
        let mut total_cost = Decimal::ZERO;

        for link in links {
            // Get traffic demand for this link
            let demand = self.get_link_demand(&link.a_end.pop_name, &link.z_end.pop_name);

            // Calculate optimal bandwidth based on mode
            let optimal_bw = match mode {
                OptimizationMode::Performance => {
                    // 50% headroom above demand
                    (demand as f64 * 1.5) as u32
                }
                OptimizationMode::Balanced => {
                    // 25% headroom
                    (demand as f64 * 1.25) as u32
                }
                OptimizationMode::Cost => {
                    // Minimum viable
                    demand
                }
            };

            // Round to standard increments
            let rounded_bw = self.round_to_increment(optimal_bw);

            // Calculate cost
            let pricing = match link.provider {
                BackboneProvider::Megaport => &self.megaport_pricing,
                BackboneProvider::PacketFabric => &self.packetfabric_pricing,
            };

            let link_cost = pricing.cost_per_mbps * Decimal::from(rounded_bw);
            total_cost += link_cost;

            allocations.insert(link.id.clone(), rounded_bw);
        }

        BandwidthPlan {
            allocations,
            total_cost,
            optimization_mode: mode,
            generated_at: Utc::now(),
        }
    }

    /// Get demand for a link
    fn get_link_demand(&self, src: &str, dst: &str) -> u32 {
        self.traffic_demands
            .iter()
            .filter(|d| {
                (d.src_pop == src && d.dst_pop == dst)
                    || (d.src_pop == dst && d.dst_pop == src)
            })
            .map(|d| d.bandwidth_mbps)
            .sum::<u32>()
            .max(100) // Minimum 100 Mbps
    }

    /// Round bandwidth to standard increments
    fn round_to_increment(&self, bw: u32) -> u32 {
        let increments = [100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000];
        *increments.iter().find(|&&i| i >= bw).unwrap_or(&100000)
    }

    /// Generate cost report
    pub fn generate_cost_report(&self, links: &[BackboneLink]) -> CostReport {
        let mut sections = HashMap::new();

        // Group by provider
        let megaport_links: Vec<_> = links.iter()
            .filter(|l| l.provider == BackboneProvider::Megaport)
            .collect();
        let pf_links: Vec<_> = links.iter()
            .filter(|l| l.provider == BackboneProvider::PacketFabric)
            .collect();

        // Calculate Megaport costs
        if !megaport_links.is_empty() {
            let port_cost = self.megaport_pricing.port_monthly * Decimal::from(megaport_links.len() as u32 * 2);
            let vxc_cost: Decimal = megaport_links.iter()
                .map(|l| self.megaport_pricing.cost_per_mbps * Decimal::from(l.bandwidth_mbps))
                .sum();
            
            sections.insert("megaport".to_string(), ProviderCost {
                provider: "Megaport".to_string(),
                port_costs: port_cost,
                vxc_costs: vxc_cost,
                burst_costs: Decimal::ZERO,
                total: port_cost + vxc_cost,
            });
        }

        // Calculate PacketFabric costs
        if !pf_links.is_empty() {
            let port_cost = self.packetfabric_pricing.port_monthly * Decimal::from(pf_links.len() as u32 * 2);
            let vxc_cost: Decimal = pf_links.iter()
                .map(|l| self.packetfabric_pricing.cost_per_mbps * Decimal::from(l.bandwidth_mbps))
                .sum();
            
            sections.insert("packetfabric".to_string(), ProviderCost {
                provider: "PacketFabric".to_string(),
                port_costs: port_cost,
                vxc_costs: vxc_cost,
                burst_costs: Decimal::ZERO,
                total: port_cost + vxc_cost,
            });
        }

        let total: Decimal = sections.values().map(|s| s.total).sum();
        let recommendations = self.generate_recommendations(links);

        CostReport {
            period_start: Utc::now(),
            period_end: Utc::now(),
            sections,
            total,
            recommendations,
        }
    }

    /// Generate cost optimization recommendations
    fn generate_recommendations(&self, links: &[BackboneLink]) -> Vec<CostRecommendation> {
        let mut recommendations = Vec::new();

        for link in links {
            let demand = self.get_link_demand(&link.a_end.pop_name, &link.z_end.pop_name);
            
            // Under-utilized links
            if link.bandwidth_mbps > demand * 2 {
                let savings = self.calculate_savings(link, demand);
                recommendations.push(CostRecommendation {
                    link_id: link.id.clone(),
                    recommendation: format!(
                        "Link under-utilized. Consider scaling from {} to {} Mbps",
                        link.bandwidth_mbps, demand
                    ),
                    potential_savings: savings,
                    action: RecommendedAction::ScaleDown {
                        current_mbps: link.bandwidth_mbps,
                        recommended_mbps: self.round_to_increment(demand),
                    },
                });
            }

            // Provider arbitrage
            let alt_provider = match link.provider {
                BackboneProvider::Megaport => BackboneProvider::PacketFabric,
                BackboneProvider::PacketFabric => BackboneProvider::Megaport,
            };
            
            let current_cost = self.get_link_cost(link);
            let alt_cost = self.get_alt_provider_cost(link, alt_provider);
            
            if alt_cost < current_cost * Decimal::new(9, 1) { // 10% cheaper
                recommendations.push(CostRecommendation {
                    link_id: link.id.clone(),
                    recommendation: format!(
                        "Consider switching to {:?} for lower cost",
                        alt_provider
                    ),
                    potential_savings: current_cost - alt_cost,
                    action: RecommendedAction::SwitchProvider {
                        from: link.provider,
                        to: alt_provider,
                    },
                });
            }
        }

        recommendations
    }

    /// Calculate savings from scaling down
    fn calculate_savings(&self, link: &BackboneLink, new_bw: u32) -> Decimal {
        let pricing = match link.provider {
            BackboneProvider::Megaport => &self.megaport_pricing,
            BackboneProvider::PacketFabric => &self.packetfabric_pricing,
        };
        
        let current_cost = pricing.cost_per_mbps * Decimal::from(link.bandwidth_mbps);
        let new_cost = pricing.cost_per_mbps * Decimal::from(new_bw);
        current_cost - new_cost
    }

    /// Get link cost
    fn get_link_cost(&self, link: &BackboneLink) -> Decimal {
        let pricing = match link.provider {
            BackboneProvider::Megaport => &self.megaport_pricing,
            BackboneProvider::PacketFabric => &self.packetfabric_pricing,
        };
        pricing.cost_per_mbps * Decimal::from(link.bandwidth_mbps)
    }

    /// Get alternative provider cost
    fn get_alt_provider_cost(&self, link: &BackboneLink, provider: BackboneProvider) -> Decimal {
        let pricing = match provider {
            BackboneProvider::Megaport => &self.megaport_pricing,
            BackboneProvider::PacketFabric => &self.packetfabric_pricing,
        };
        pricing.cost_per_mbps * Decimal::from(link.bandwidth_mbps)
    }
}

impl Default for CostOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_rounding() {
        let optimizer = CostOptimizer::new();
        assert_eq!(optimizer.round_to_increment(150), 200);
        assert_eq!(optimizer.round_to_increment(600), 1000);
        assert_eq!(optimizer.round_to_increment(3000), 5000);
    }

    #[test]
    fn test_cost_report_generation() {
        let optimizer = CostOptimizer::new();
        let links = vec![
            BackboneLink {
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
                status: crate::VxcStatus::Active,
                latency_ms: Some(35.0),
                monthly_cost: Decimal::from(1000),
            },
        ];

        let report = optimizer.generate_cost_report(&links);
        assert!(report.sections.contains_key("megaport"));
        assert!(report.total > Decimal::ZERO);
    }
}
