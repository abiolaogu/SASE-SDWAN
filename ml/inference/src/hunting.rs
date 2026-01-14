//! Threat Hunting Interface

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Threat hunting manager
pub struct HuntingManager {
    /// Saved hunts
    hunts: Arc<RwLock<Vec<SavedHunt>>>,
}

impl HuntingManager {
    pub fn new() -> Self {
        Self {
            hunts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Execute hunt query
    pub async fn execute(&self, query: HuntQuery) -> HuntResult {
        tracing::info!("Executing hunt: {}", query.name);
        
        // In production: query historical data
        let matches = self.run_query(&query).await;
        
        HuntResult {
            query_id: uuid::Uuid::new_v4().to_string(),
            query_name: query.name,
            match_count: matches.len(),
            matches,
            execution_time_ms: 250,
        }
    }

    /// Save hunt for later
    pub fn save_hunt(&self, hunt: SavedHunt) {
        self.hunts.write().push(hunt);
    }

    /// Get saved hunts
    pub fn get_hunts(&self) -> Vec<SavedHunt> {
        self.hunts.read().clone()
    }

    async fn run_query(&self, query: &HuntQuery) -> Vec<HuntMatch> {
        let mut matches = Vec::new();
        
        // Example: DNS entropy query
        if let Some(threshold) = query.conditions.get("dns_entropy_gt") {
            let threshold: f64 = threshold.parse().unwrap_or(3.5);
            // In production: query DNS logs
            matches.push(HuntMatch {
                timestamp: chrono::Utc::now().timestamp() as u64,
                entity_type: "domain".into(),
                entity_value: "xkj3gh2.example.com".into(),
                matched_field: "entropy".into(),
                matched_value: "4.2".into(),
                context: HashMap::new(),
            });
        }
        
        matches
    }
}

impl Default for HuntingManager {
    fn default() -> Self { Self::new() }
}

/// Hunt query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntQuery {
    pub name: String,
    pub description: String,
    pub data_source: DataSource,
    pub conditions: HashMap<String, String>,
    pub time_range: TimeRange,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DataSource {
    DnsLogs,
    FlowLogs,
    UserActivity,
    Alerts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: u64,
    pub end: u64,
}

/// Hunt result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResult {
    pub query_id: String,
    pub query_name: String,
    pub match_count: usize,
    pub matches: Vec<HuntMatch>,
    pub execution_time_ms: u64,
}

/// Hunt match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntMatch {
    pub timestamp: u64,
    pub entity_type: String,
    pub entity_value: String,
    pub matched_field: String,
    pub matched_value: String,
    pub context: HashMap<String, String>,
}

/// Saved hunt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedHunt {
    pub id: String,
    pub name: String,
    pub query: HuntQuery,
    pub created_by: String,
    pub created_at: u64,
}

/// Pre-built hunt templates
pub fn get_hunt_templates() -> Vec<HuntQuery> {
    vec![
        HuntQuery {
            name: "High Entropy DNS".into(),
            description: "Find DNS queries with entropy > 4.0 (potential DGA)".into(),
            data_source: DataSource::DnsLogs,
            conditions: [("dns_entropy_gt".into(), "4.0".into())].into(),
            time_range: TimeRange { start: 0, end: 0 },
        },
        HuntQuery {
            name: "Large Data Uploads".into(),
            description: "Find uploads > 100MB to external destinations".into(),
            data_source: DataSource::FlowLogs,
            conditions: [
                ("bytes_uploaded_gt".into(), "104857600".into()),
                ("destination".into(), "external".into()),
            ].into(),
            time_range: TimeRange { start: 0, end: 0 },
        },
        HuntQuery {
            name: "Off-Hours Access".into(),
            description: "Find user activity outside business hours".into(),
            data_source: DataSource::UserActivity,
            conditions: [("hour_outside".into(), "6-22".into())].into(),
            time_range: TimeRange { start: 0, end: 0 },
        },
    ]
}
