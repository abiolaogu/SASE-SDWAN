//! Capacity Planning

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;

/// Capacity Planner
pub struct CapacityPlanner {
    /// PoP capacity
    capacities: Arc<RwLock<HashMap<Uuid, PopCapacity>>>,
    /// Forecasts
    forecasts: Arc<RwLock<HashMap<Uuid, TrafficForecast>>>,
    /// Procurement requests
    procurements: Arc<RwLock<Vec<ProcurementRequest>>>,
}

impl CapacityPlanner {
    pub fn new() -> Self {
        Self {
            capacities: Arc::new(RwLock::new(HashMap::new())),
            forecasts: Arc::new(RwLock::new(HashMap::new())),
            procurements: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record current capacity
    pub fn set_capacity(&self, pop_id: Uuid, capacity: PopCapacity) {
        self.capacities.write().insert(pop_id, capacity);
    }

    /// Update traffic forecast
    pub fn update_forecast(&self, pop_id: Uuid, forecast: TrafficForecast) {
        self.forecasts.write().insert(pop_id, forecast);
    }

    /// Check capacity thresholds
    pub fn check_thresholds(&self) -> Vec<CapacityAlert> {
        let capacities = self.capacities.read();
        let forecasts = self.forecasts.read();
        let mut alerts = Vec::new();

        for (pop_id, capacity) in capacities.iter() {
            let utilization = capacity.current_traffic_gbps / capacity.total_capacity_gbps;

            // Alert at 80% utilization
            if utilization > 0.8 {
                alerts.push(CapacityAlert {
                    pop_id: *pop_id,
                    alert_type: CapacityAlertType::HighUtilization,
                    current_utilization: utilization,
                    message: format!("PoP at {:.1}% capacity", utilization * 100.0),
                });
            }

            // Check if forecast exceeds capacity
            if let Some(forecast) = forecasts.get(pop_id) {
                if forecast.projected_30d_gbps > capacity.total_capacity_gbps {
                    alerts.push(CapacityAlert {
                        pop_id: *pop_id,
                        alert_type: CapacityAlertType::ForecastExceedsCapacity,
                        current_utilization: utilization,
                        message: format!(
                            "30-day forecast ({:.1} Gbps) exceeds capacity ({:.1} Gbps)",
                            forecast.projected_30d_gbps, capacity.total_capacity_gbps
                        ),
                    });
                }
            }

            // Check commit utilization
            if capacity.current_traffic_gbps > capacity.commit_gbps * 0.9 {
                alerts.push(CapacityAlert {
                    pop_id: *pop_id,
                    alert_type: CapacityAlertType::ApproachingCommit,
                    current_utilization: utilization,
                    message: format!("Approaching commit limit at {:.1} Gbps", capacity.current_traffic_gbps),
                });
            }
        }

        alerts
    }

    /// Generate procurement request
    pub fn request_capacity(&self, pop_id: Uuid, additional_gbps: u64, reason: &str) -> Uuid {
        let request = ProcurementRequest {
            id: Uuid::new_v4(),
            pop_id,
            requested_capacity_gbps: additional_gbps,
            reason: reason.to_string(),
            status: ProcurementStatus::Pending,
            created_at: chrono::Utc::now(),
            estimated_cost_monthly: additional_gbps as f64 * 500.0, // $500/Gbps estimate
        };
        let id = request.id;
        self.procurements.write().push(request);
        id
    }

    /// Get pending procurements
    pub fn get_pending_procurements(&self) -> Vec<ProcurementRequest> {
        self.procurements.read()
            .iter()
            .filter(|p| p.status == ProcurementStatus::Pending)
            .cloned()
            .collect()
    }
}

impl Default for CapacityPlanner {
    fn default() -> Self { Self::new() }
}

/// PoP capacity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopCapacity {
    pub pop_id: Uuid,
    pub total_capacity_gbps: f64,
    pub commit_gbps: f64,
    pub current_traffic_gbps: f64,
    pub port_count: u32,
    pub providers: Vec<ProviderCapacity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCapacity {
    pub name: String,
    pub capacity_gbps: f64,
    pub commit_gbps: f64,
}

/// Traffic forecast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficForecast {
    pub pop_id: Uuid,
    pub current_gbps: f64,
    pub projected_7d_gbps: f64,
    pub projected_30d_gbps: f64,
    pub projected_90d_gbps: f64,
    pub growth_rate_monthly: f64,
}

/// Capacity alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityAlert {
    pub pop_id: Uuid,
    pub alert_type: CapacityAlertType,
    pub current_utilization: f64,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CapacityAlertType {
    HighUtilization,
    ForecastExceedsCapacity,
    ApproachingCommit,
    ProviderDown,
}

/// Procurement request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcurementRequest {
    pub id: Uuid,
    pub pop_id: Uuid,
    pub requested_capacity_gbps: u64,
    pub reason: String,
    pub status: ProcurementStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub estimated_cost_monthly: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcurementStatus {
    Pending,
    Approved,
    Ordered,
    Provisioning,
    Active,
    Rejected,
}
