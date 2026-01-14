//! Traffic Optimizer - Ties everything together

use crate::telemetry::TelemetryCollector;
use crate::classifier::{AppClassifier, AppCategory, FlowFeatures};
use crate::path::{PathSelector, PathSelection};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Traffic optimizer
pub struct TrafficOptimizer {
    telemetry: Arc<TelemetryCollector>,
    classifier: AppClassifier,
    selector: Arc<RwLock<PathSelector>>,
    /// Active flow → path assignments
    flows: Arc<RwLock<HashMap<u64, FlowAssignment>>>,
}

impl TrafficOptimizer {
    /// Create new optimizer
    pub fn new(telemetry: Arc<TelemetryCollector>) -> Self {
        let selector = PathSelector::new(telemetry.clone());
        
        Self {
            telemetry,
            classifier: AppClassifier::new(),
            selector: Arc::new(RwLock::new(selector)),
            flows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Process new flow - classify and assign path
    pub fn process_flow(
        &self,
        flow_id: u64,
        dst_port: u16,
        protocol: u8,
        features: &FlowFeatures,
        payload: &[u8],
        destination: &str,
    ) -> FlowDecision {
        // 1. Classify traffic
        let classification = self.classifier.classify(dst_port, protocol, features, payload);
        
        // 2. Select optimal path
        let selection = self.selector.read()
            .select(destination, classification.category);
        
        let path_id = selection.as_ref()
            .map(|s| s.path_id.clone())
            .unwrap_or_else(|| "default".to_string());

        // 3. Record assignment
        let assignment = FlowAssignment {
            flow_id,
            category: classification.category,
            path_id: path_id.clone(),
            assigned_at: now(),
            last_check: now(),
        };
        self.flows.write().insert(flow_id, assignment);

        FlowDecision {
            flow_id,
            category: classification.category,
            confidence: classification.confidence,
            app_name: classification.app_name,
            path_id,
            dscp: classification.category.dscp(),
            reason: selection.map(|s| s.reason).unwrap_or_default(),
        }
    }

    /// Re-evaluate existing flow
    pub fn reevaluate_flow(&self, flow_id: u64, destination: &str) -> Option<FlowDecision> {
        let assignment = self.flows.read().get(&flow_id)?.clone();
        
        // Check if path switch is needed
        let new_path = self.selector.read()
            .should_switch(&assignment.path_id, destination, assignment.category)?;
        
        // Update assignment
        let mut flows = self.flows.write();
        if let Some(a) = flows.get_mut(&flow_id) {
            a.path_id = new_path.path_id.clone();
            a.last_check = now();
        }

        Some(FlowDecision {
            flow_id,
            category: assignment.category,
            confidence: 1.0,
            app_name: None,
            path_id: new_path.path_id,
            dscp: assignment.category.dscp(),
            reason: format!("Path switch: {}", new_path.reason),
        })
    }

    /// Get flow count by category
    pub fn flow_stats(&self) -> HashMap<AppCategory, usize> {
        let flows = self.flows.read();
        let mut stats = HashMap::new();
        
        for assignment in flows.values() {
            *stats.entry(assignment.category).or_insert(0) += 1;
        }
        stats
    }

    /// Remove finished flow
    pub fn remove_flow(&self, flow_id: u64) {
        self.flows.write().remove(&flow_id);
    }

    /// Get path selector for configuration
    pub fn path_selector(&self) -> Arc<RwLock<PathSelector>> {
        self.selector.clone()
    }
}

/// Flow assignment
#[derive(Debug, Clone)]
pub struct FlowAssignment {
    pub flow_id: u64,
    pub category: AppCategory,
    pub path_id: String,
    pub assigned_at: u64,
    pub last_check: u64,
}

/// Flow decision
#[derive(Debug, Clone)]
pub struct FlowDecision {
    pub flow_id: u64,
    pub category: AppCategory,
    pub confidence: f64,
    pub app_name: Option<String>,
    pub path_id: String,
    pub dscp: u8,
    pub reason: String,
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
    fn test_flow_processing() {
        let telemetry = Arc::new(TelemetryCollector::default());
        let optimizer = TrafficOptimizer::new(telemetry);
        
        let features = FlowFeatures {
            avg_packet_size: 200.0,
            packets_per_sec: 50.0,
            ..Default::default()
        };
        
        let decision = optimizer.process_flow(
            1, 5060, 17, &features, &[], "voip.example.com"
        );
        
        assert_eq!(decision.category, AppCategory::VoiceVideo);
        assert_eq!(decision.dscp, 46);
    }

    #[test]
    fn test_flow_stats() {
        let telemetry = Arc::new(TelemetryCollector::default());
        let optimizer = TrafficOptimizer::new(telemetry);
        
        let features = FlowFeatures::default();
        
        optimizer.process_flow(1, 5060, 17, &features, &[], "a.com");
        optimizer.process_flow(2, 443, 6, &features, &[], "b.com");
        optimizer.process_flow(3, 443, 6, &features, &[], "c.com");
        
        let stats = optimizer.flow_stats();
        assert!(stats.len() >= 1);
    }
}
