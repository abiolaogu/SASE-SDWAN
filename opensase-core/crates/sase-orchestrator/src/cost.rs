//! Multi-Cloud Cost Optimization

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::provider::CloudProvider;

/// Cost tracker and optimizer
pub struct CostOptimizer {
    /// Egress costs per provider ($ per GB)
    egress_costs: HashMap<CloudProvider, f64>,
    /// Usage data per PoP
    usage: HashMap<String, UsageData>,
    /// Peering agreements (provider pairs with reduced costs)
    peering: Vec<(CloudProvider, CloudProvider)>,
}

impl CostOptimizer {
    pub fn new() -> Self {
        let mut egress_costs = HashMap::new();
        
        // Typical egress costs ($ per GB)
        egress_costs.insert(CloudProvider::Aws, 0.09);
        egress_costs.insert(CloudProvider::Gcp, 0.08);
        egress_costs.insert(CloudProvider::Azure, 0.087);
        egress_costs.insert(CloudProvider::Vultr, 0.01);  // Much cheaper
        egress_costs.insert(CloudProvider::DigitalOcean, 0.01);
        egress_costs.insert(CloudProvider::Linode, 0.005);  // Cheapest
        egress_costs.insert(CloudProvider::Hetzner, 0.0);  // Free up to limit
        egress_costs.insert(CloudProvider::EquinixMetal, 0.05);

        Self {
            egress_costs,
            usage: HashMap::new(),
            peering: vec![
                (CloudProvider::Aws, CloudProvider::Aws),  // Same provider = free
                (CloudProvider::Gcp, CloudProvider::Gcp),
            ],
        }
    }

    /// Get egress cost for provider
    pub fn egress_cost(&self, provider: CloudProvider) -> f64 {
        *self.egress_costs.get(&provider).unwrap_or(&0.1)
    }

    /// Record usage
    pub fn record_usage(&mut self, pop_id: &str, egress_gb: f64, compute_hours: f64) {
        let entry = self.usage.entry(pop_id.to_string()).or_default();
        entry.egress_gb += egress_gb;
        entry.compute_hours += compute_hours;
    }

    /// Calculate cost for PoP
    pub fn calculate_pop_cost(&self, pop_id: &str, provider: CloudProvider) -> PopCost {
        let usage = self.usage.get(pop_id).cloned().unwrap_or_default();
        let egress_rate = self.egress_cost(provider);
        
        let egress_cost = usage.egress_gb * egress_rate;
        let compute_cost = usage.compute_hours * 0.05;  // $0.05/hr estimate
        
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
    pub fn cheapest_route(&self, from: CloudProvider, to: CloudProvider) -> RouteCost {
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

        // Direct route cost
        let direct_cost = self.egress_cost(from) + self.egress_cost(to);
        
        // Check if routing through a different provider is cheaper
        let mut best_cost = direct_cost;
        let mut best_path = vec![from, to];

        for (&mid, _) in &self.egress_costs {
            if mid == from || mid == to { continue; }
            
            let via_cost = self.egress_cost(from) + self.egress_cost(mid) + self.egress_cost(to);
            // This is rarely cheaper, but check for peering savings
            
            if via_cost < best_cost {
                best_cost = via_cost;
                best_path = vec![from, mid, to];
            }
        }

        RouteCost {
            cost_per_gb: best_cost,
            path: best_path,
            has_peering: false,
        }
    }

    /// Generate cost report
    pub fn generate_report(&self, pops: &[(String, CloudProvider)]) -> CostReport {
        let mut pop_costs = Vec::new();
        let mut total = 0.0;

        for (pop_id, provider) in pops {
            let cost = self.calculate_pop_cost(pop_id, *provider);
            total += cost.total_cost;
            pop_costs.push(cost);
        }

        // Find most expensive
        pop_costs.sort_by(|a, b| b.total_cost.partial_cmp(&a.total_cost).unwrap());

        CostReport {
            period_start: now() - 86400 * 30,  // Last 30 days
            period_end: now(),
            pop_costs,
            total_cost: total,
            currency: "USD".into(),
        }
    }

    /// Get optimization recommendations
    pub fn recommendations(&self, pops: &[(String, CloudProvider)]) -> Vec<Recommendation> {
        let mut recs = Vec::new();

        for (pop_id, provider) in pops {
            let cost = self.calculate_pop_cost(pop_id, *provider);
            
            // Check if a cheaper provider exists
            for (&alt_provider, &alt_cost) in &self.egress_costs {
                if alt_provider == *provider { continue; }
                
                let savings = cost.egress_gb * (self.egress_cost(*provider) - alt_cost);
                if savings > 100.0 {  // Min $100 savings to recommend
                    recs.push(Recommendation {
                        pop_id: pop_id.clone(),
                        recommendation: format!(
                            "Move to {:?} to save ${:.2}/month on egress",
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
    pub path: Vec<CloudProvider>,
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
    fn test_cost_comparison() {
        let opt = CostOptimizer::new();
        
        assert!(opt.egress_cost(CloudProvider::Linode) < opt.egress_cost(CloudProvider::Aws));
        assert!(opt.egress_cost(CloudProvider::Vultr) < opt.egress_cost(CloudProvider::Azure));
    }

    #[test]
    fn test_cheapest_route() {
        let opt = CostOptimizer::new();
        
        // Same provider should be free
        let route = opt.cheapest_route(CloudProvider::Aws, CloudProvider::Aws);
        assert_eq!(route.cost_per_gb, 0.0);
        assert!(route.has_peering);
    }

    #[test]
    fn test_usage_tracking() {
        let mut opt = CostOptimizer::new();
        
        opt.record_usage("pop-us", 1000.0, 720.0);  // 1TB, 720 hours
        
        let cost = opt.calculate_pop_cost("pop-us", CloudProvider::Aws);
        assert!(cost.egress_cost > 0.0);
        assert!(cost.total_cost > cost.egress_cost);
    }
}
