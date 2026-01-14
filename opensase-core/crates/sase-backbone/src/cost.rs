//! Cost Optimization Engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rust_decimal::Decimal;
use uuid::Uuid;

/// Cost Optimizer
pub struct CostOptimizer {
    /// Provider costs
    providers: Arc<RwLock<HashMap<Uuid, ProviderCost>>>,
    /// Traffic usage
    usage: Arc<RwLock<HashMap<Uuid, TrafficUsage>>>,
    /// Cost alerts
    alerts: Arc<RwLock<Vec<CostAlert>>>,
}

impl CostOptimizer {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            usage: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add provider cost definition
    pub fn add_provider(&self, cost: ProviderCost) -> Uuid {
        let id = cost.id;
        self.providers.write().insert(id, cost);
        id
    }

    /// Get all costs
    pub fn get_all_costs(&self) -> Vec<ProviderCost> {
        self.providers.read().values().cloned().collect()
    }

    /// Update traffic usage
    pub fn update_usage(&self, provider_id: Uuid, bytes: u64) {
        let mut usage = self.usage.write();
        let entry = usage.entry(provider_id).or_insert(TrafficUsage::default());
        entry.bytes_total += bytes;
        entry.last_updated = chrono::Utc::now();
        
        // Check for commit overage
        if let Some(provider) = self.providers.read().get(&provider_id) {
            let mbps = (entry.bytes_total as f64 / 1_000_000.0) / 
                       (chrono::Utc::now().timestamp() - entry.period_start.timestamp()) as f64 * 8.0;
            
            if mbps > provider.commit_mbps as f64 * 0.9 {
                self.alerts.write().push(CostAlert {
                    id: Uuid::new_v4(),
                    provider_id,
                    alert_type: AlertType::ApproachingCommit,
                    message: format!("Provider {} at {:.1}% of commit", provider.provider, (mbps / provider.commit_mbps as f64) * 100.0),
                    created_at: chrono::Utc::now(),
                });
            }
        }
    }

    /// Calculate optimal traffic placement
    pub fn optimize_placement(&self, traffic_mbps: u64) -> Vec<TrafficPlacement> {
        let providers = self.providers.read();
        let usage = self.usage.read();
        let mut placements = Vec::new();

        // Sort providers by effective cost
        let mut sorted: Vec<_> = providers.values().cloned().collect();
        sorted.sort_by(|a, b| {
            let cost_a = self.effective_cost(a, &usage);
            let cost_b = self.effective_cost(b, &usage);
            cost_a.partial_cmp(&cost_b).unwrap()
        });

        let mut remaining = traffic_mbps;
        for provider in &sorted {
            let current_usage = usage.get(&provider.id)
                .map(|u| u.bytes_total / 125_000) // Convert to Mbps-seconds estimate
                .unwrap_or(0);
            
            let available = provider.commit_mbps.saturating_sub(current_usage as u64);
            let allocate = remaining.min(available);
            
            if allocate > 0 {
                placements.push(TrafficPlacement {
                    provider_id: provider.id,
                    provider_name: provider.provider.clone(),
                    mbps: allocate,
                    cost_category: if allocate <= available { CostCategory::Commit } else { CostCategory::Burst },
                });
                remaining -= allocate;
            }

            if remaining == 0 {
                break;
            }
        }

        // Any remaining goes to burst on cheapest provider
        if remaining > 0 {
            if let Some(provider) = sorted.first() {
                placements.push(TrafficPlacement {
                    provider_id: provider.id,
                    provider_name: provider.provider.clone(),
                    mbps: remaining,
                    cost_category: CostCategory::Burst,
                });
            }
        }

        placements
    }

    /// Calculate effective cost per Mbps
    fn effective_cost(&self, provider: &ProviderCost, usage: &HashMap<Uuid, TrafficUsage>) -> f64 {
        let current = usage.get(&provider.id)
            .map(|u| u.bytes_total / 125_000)
            .unwrap_or(0) as u64;

        if current < provider.commit_mbps {
            // Within commit: cost is fixed / commit
            provider.commit_cost.to_string().parse::<f64>().unwrap_or(0.0) / provider.commit_mbps as f64
        } else {
            // Burst: use burst rate
            provider.burst_rate.to_string().parse::<f64>().unwrap_or(1.0)
        }
    }

    /// Get monthly cost projection
    pub fn project_monthly_cost(&self) -> MonthlyCostProjection {
        let providers = self.providers.read();
        let usage = self.usage.read();
        let mut total = Decimal::ZERO;
        let mut by_provider = Vec::new();

        for provider in providers.values() {
            let current_usage = usage.get(&provider.id).cloned().unwrap_or_default();
            let days_elapsed = 15.0; // Approximate
            let projected_mbps = (current_usage.bytes_total as f64 / 125_000.0 / days_elapsed) * 30.0;
            
            let cost = if projected_mbps as u64 <= provider.commit_mbps {
                provider.commit_cost
            } else {
                let overage = (projected_mbps as u64 - provider.commit_mbps) as f64;
                provider.commit_cost + provider.burst_rate * Decimal::from_f64_retain(overage).unwrap_or_default()
            };

            total += cost;
            by_provider.push((provider.provider.clone(), cost));
        }

        MonthlyCostProjection { total, by_provider }
    }
}

impl Default for CostOptimizer {
    fn default() -> Self { Self::new() }
}

/// Provider cost definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCost {
    pub id: Uuid,
    pub provider: String,
    pub pop_id: Uuid,
    pub commit_mbps: u64,
    pub commit_cost: Decimal,
    pub burst_rate: Decimal, // per Mbps over commit
    pub billing_type: BillingType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BillingType {
    NinetyFifthPercentile,
    Flat,
    PerGB,
}

/// Traffic usage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficUsage {
    pub bytes_total: u64,
    pub period_start: chrono::DateTime<chrono::Utc>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Traffic placement recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPlacement {
    pub provider_id: Uuid,
    pub provider_name: String,
    pub mbps: u64,
    pub cost_category: CostCategory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CostCategory {
    Commit,
    Burst,
    Peering, // Free
}

/// Cost alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostAlert {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub alert_type: AlertType,
    pub message: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertType {
    ApproachingCommit,
    OverCommit,
    ProviderDown,
}

/// Monthly cost projection
#[derive(Debug, Clone)]
pub struct MonthlyCostProjection {
    pub total: Decimal,
    pub by_provider: Vec<(String, Decimal)>,
}
