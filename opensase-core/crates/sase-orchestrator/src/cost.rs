//! Dedicated Server Cost Optimization
//!
//! Cost tracking and optimization for dedicated server providers.
//! Dedicated servers typically have fixed monthly costs and generous/unlimited bandwidth.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::provider::{DedicatedProvider, CloudProvider};

/// Cost tracker and optimizer for dedicated servers
pub struct CostOptimizer {
    /// Monthly base costs per provider/config
    monthly_costs: HashMap<DedicatedProvider, f64>,
    /// Egress costs per provider ($ per GB) - most are 0 for dedicated
    egress_costs: HashMap<DedicatedProvider, f64>,
    /// Usage data per PoP
    usage: HashMap<String, UsageData>,
    /// Peering agreements (provider pairs with private interconnect)
    peering: Vec<(DedicatedProvider, DedicatedProvider)>,
}

impl CostOptimizer {
    pub fn new() -> Self {
        let mut monthly_costs = HashMap::new();
        let mut egress_costs = HashMap::new();
        
        // Dedicated server monthly costs (base estimates)
        monthly_costs.insert(DedicatedProvider::Hetzner, 50.0);        // Excellent value
        monthly_costs.insert(DedicatedProvider::OvhCloud, 80.0);       // Good value
        monthly_costs.insert(DedicatedProvider::Scaleway, 70.0);       // EU focused
        monthly_costs.insert(DedicatedProvider::Voxility, 150.0);      // Premium DDoS protection
        monthly_costs.insert(DedicatedProvider::EquinixMetal, 500.0);  // Premium bare metal
        monthly_costs.insert(DedicatedProvider::Leaseweb, 100.0);      // Global coverage
        monthly_costs.insert(DedicatedProvider::PhoenixNap, 200.0);    // BMC platform
        
        // Egress costs ($ per GB) - most dedicated providers include generous transfer
        egress_costs.insert(DedicatedProvider::Hetzner, 0.0);         // 20TB+ included
        egress_costs.insert(DedicatedProvider::OvhCloud, 0.0);         // Unlimited included
        egress_costs.insert(DedicatedProvider::Scaleway, 0.0);         // 1TB+ included
        egress_costs.insert(DedicatedProvider::Voxility, 0.002);       // Very cheap
        egress_costs.insert(DedicatedProvider::EquinixMetal, 0.05);    // Premium
        egress_costs.insert(DedicatedProvider::Leaseweb, 0.0);         // Included
        egress_costs.insert(DedicatedProvider::PhoenixNap, 0.01);      // Reasonable

        Self {
            monthly_costs,
            egress_costs,
            usage: HashMap::new(),
            peering: vec![
                // Private interconnects between providers
                (DedicatedProvider::Hetzner, DedicatedProvider::Hetzner),
                (DedicatedProvider::OvhCloud, DedicatedProvider::OvhCloud),
                (DedicatedProvider::EquinixMetal, DedicatedProvider::EquinixMetal),
            ],
        }
    }

    /// Get egress cost for provider
    pub fn egress_cost(&self, provider: DedicatedProvider) -> f64 {
        *self.egress_costs.get(&provider).unwrap_or(&0.01)
    }

    /// Get monthly base cost for provider
    pub fn monthly_base_cost(&self, provider: DedicatedProvider) -> f64 {
        *self.monthly_costs.get(&provider).unwrap_or(&100.0)
    }

    /// Record usage
    pub fn record_usage(&mut self, pop_id: &str, egress_gb: f64, compute_hours: f64) {
        let entry = self.usage.entry(pop_id.to_string()).or_default();
        entry.egress_gb += egress_gb;
        entry.compute_hours += compute_hours;
    }

    /// Calculate cost for PoP
    pub fn calculate_pop_cost(&self, pop_id: &str, provider: DedicatedProvider) -> PopCost {
        let usage = self.usage.get(pop_id).cloned().unwrap_or_default();
        let egress_rate = self.egress_cost(provider);
        let monthly_base = self.monthly_base_cost(provider);
        
        // Egress cost (usually 0 or very low for dedicated)
        let egress_cost = usage.egress_gb * egress_rate;
        
        // Compute cost is fixed monthly for dedicated servers
        let compute_cost = monthly_base;
        
        PopCost {
            pop_id: pop_id.to_string(),
            egress_gb: usage.egress_gb,
            egress_cost,
            compute_hours: usage.compute_hours,
            compute_cost,
            total_cost: egress_cost + compute_cost,
        }
    }

    /// Find cheapest path between providers
    pub fn cheapest_route(&self, from: DedicatedProvider, to: DedicatedProvider) -> RouteCost {
        // Check if peering exists
        let has_peering = self.peering.iter().any(|(a, b)| 
            (*a == from && *b == to) || (*a == to && *b == from)
        );

        if from == to || has_peering {
            return RouteCost {
                cost_per_gb: 0.0,
                path: vec![from, to],
                has_peering: true,
            };
        }

        // Direct route cost (egress only - dedicated doesn't charge ingress)
        let direct_cost = self.egress_cost(from);
        
        RouteCost {
            cost_per_gb: direct_cost,
            path: vec![from, to],
            has_peering: false,
        }
    }

    /// Optimize placement - prefer cost-effective dedicated providers
    pub fn optimize_placement(&self, requirements: &PlacementRequirements) -> Vec<ProviderRecommendation> {
        let mut recommendations = Vec::new();
        
        // Sort providers by cost-effectiveness
        let mut sorted: Vec<_> = self.monthly_costs.iter().collect();
        sorted.sort_by(|a, b| a.1.partial_cmp(b.1).unwrap());
        
        for (provider, cost) in &sorted {
            // Check if provider meets requirements
            if requirements.needs_bgp && !provider.supports_bgp() {
                continue;
            }
            if requirements.needs_anycast && !provider.supports_anycast() {
                continue;
            }
            
            let regions = provider.regions();
            if !requirements.required_regions.is_empty() {
                let has_region = requirements.required_regions.iter()
                    .any(|r| regions.iter().any(|pr| pr.contains(r)));
                if !has_region {
                    continue;
                }
            }
            
            recommendations.push(ProviderRecommendation {
                provider: **provider,
                monthly_cost: **cost,
                egress_cost_per_gb: self.egress_cost(**provider),
                reasons: vec![
                    format!("Monthly cost: ${:.0}", cost),
                    format!("Egress: ${:.3}/GB", self.egress_cost(**provider)),
                ],
            });
        }
        
        recommendations
    }

    /// Generate cost report
    pub fn generate_report(&self, pops: &[(String, DedicatedProvider)]) -> CostReport {
        let mut pop_costs = Vec::new();
        let mut total = 0.0;

        for (pop_id, provider) in pops {
            let cost = self.calculate_pop_cost(pop_id, *provider);
            total += cost.total_cost;
            pop_costs.push(cost);
        }

        pop_costs.sort_by(|a, b| b.total_cost.partial_cmp(&a.total_cost).unwrap());

        CostReport {
            period_start: now() - 86400 * 30,
            period_end: now(),
            pop_costs,
            total_cost: total,
            currency: "USD".into(),
        }
    }

    /// Get optimization recommendations
    pub fn recommendations(&self, pops: &[(String, DedicatedProvider)]) -> Vec<Recommendation> {
        let mut recs = Vec::new();

        for (pop_id, provider) in pops {
            let current_cost = self.calculate_pop_cost(pop_id, *provider);
            
            // Find cheaper alternatives
            for (&alt_provider, &alt_monthly) in &self.monthly_costs {
                if alt_provider == *provider { continue; }
                
                let alt_total = alt_monthly + (current_cost.egress_gb * self.egress_cost(alt_provider));
                let savings = current_cost.total_cost - alt_total;
                
                if savings > 50.0 {  // Min $50/month savings
                    recs.push(Recommendation {
                        pop_id: pop_id.clone(),
                        recommendation: format!(
                            "Migrate to {:?} - save ${:.0}/month",
                            alt_provider, savings
                        ),
                        estimated_savings: savings,
                    });
                }
            }
        }

        recs.sort_by(|a, b| b.estimated_savings.partial_cmp(&a.estimated_savings).unwrap());
        recs
    }
}

impl Default for CostOptimizer {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone, Default)]
pub struct UsageData {
    pub egress_gb: f64,
    pub compute_hours: f64,
}

#[derive(Debug, Clone, Default)]
pub struct PlacementRequirements {
    pub needs_bgp: bool,
    pub needs_anycast: bool,
    pub required_regions: Vec<String>,
    pub min_bandwidth_gbps: u32,
}

#[derive(Debug, Clone)]
pub struct ProviderRecommendation {
    pub provider: DedicatedProvider,
    pub monthly_cost: f64,
    pub egress_cost_per_gb: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PopCost {
    pub pop_id: String,
    pub egress_gb: f64,
    pub egress_cost: f64,
    pub compute_hours: f64,
    pub compute_cost: f64,
    pub total_cost: f64,
}

#[derive(Debug, Clone)]
pub struct RouteCost {
    pub cost_per_gb: f64,
    pub path: Vec<DedicatedProvider>,
    pub has_peering: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CostReport {
    pub period_start: u64,
    pub period_end: u64,
    pub pop_costs: Vec<PopCost>,
    pub total_cost: f64,
    pub currency: String,
}

#[derive(Debug, Clone)]
pub struct Recommendation {
    pub pop_id: String,
    pub recommendation: String,
    pub estimated_savings: f64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedicated_cost_comparison() {
        let opt = CostOptimizer::new();
        
        // Hetzner should be cheapest
        assert!(opt.monthly_base_cost(DedicatedProvider::Hetzner) < 
                opt.monthly_base_cost(DedicatedProvider::EquinixMetal));
        
        // Most dedicated have free egress
        assert_eq!(opt.egress_cost(DedicatedProvider::Hetzner), 0.0);
        assert_eq!(opt.egress_cost(DedicatedProvider::OvhCloud), 0.0);
    }

    #[test]
    fn test_cheapest_route_peering() {
        let opt = CostOptimizer::new();
        
        // Same provider should be free
        let route = opt.cheapest_route(DedicatedProvider::Hetzner, DedicatedProvider::Hetzner);
        assert_eq!(route.cost_per_gb, 0.0);
        assert!(route.has_peering);
    }

    #[test]
    fn test_usage_tracking() {
        let mut opt = CostOptimizer::new();
        
        opt.record_usage("pop-eu", 5000.0, 720.0);  // 5TB, 720 hours
        
        // With Hetzner, egress should be free
        let cost = opt.calculate_pop_cost("pop-eu", DedicatedProvider::Hetzner);
        assert_eq!(cost.egress_cost, 0.0);  // Free egress
        assert!(cost.compute_cost > 0.0);   // Monthly cost
    }

    #[test]
    fn test_optimize_placement() {
        let opt = CostOptimizer::new();
        
        let requirements = PlacementRequirements {
            needs_bgp: true,
            needs_anycast: false,
            required_regions: vec![],
            min_bandwidth_gbps: 1,
        };
        
        let recs = opt.optimize_placement(&requirements);
        assert!(!recs.is_empty());
        
        // Should be sorted by cost
        if recs.len() >= 2 {
            assert!(recs[0].monthly_cost <= recs[1].monthly_cost);
        }
    }
}
