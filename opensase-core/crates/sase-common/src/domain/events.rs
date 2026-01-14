//! Domain Events - Record significant occurrences in the domain
//!
//! Events are:
//! - Immutable records of past occurrences
//! - Named in past tense
//! - Used for event sourcing and integration

use super::value_objects::*;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Base event metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Unique event ID
    pub event_id: String,
    /// Timestamp
    pub timestamp: u64,
    /// Aggregate ID
    pub aggregate_id: String,
    /// Aggregate type
    pub aggregate_type: String,
    /// Version after event
    pub version: u64,
}

impl EventMetadata {
    pub fn new(aggregate_id: &str, aggregate_type: &str, version: u64) -> Self {
        Self {
            event_id: uuid_v4(),
            timestamp: now_millis(),
            aggregate_id: aggregate_id.to_string(),
            aggregate_type: aggregate_type.to_string(),
            version,
        }
    }
}

/// Domain event trait
pub trait DomainEvent: Send + Sync {
    fn event_type(&self) -> &'static str;
    fn metadata(&self) -> &EventMetadata;
}

// === Policy Context Events ===

/// Policy was created
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCreated {
    pub metadata: EventMetadata,
    pub policy_id: String,
    pub default_action: String,
}

impl DomainEvent for PolicyCreated {
    fn event_type(&self) -> &'static str { "policy.created" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

/// Rule was added to policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAdded {
    pub metadata: EventMetadata,
    pub rule_id: u32,
    pub priority: u16,
    pub action: String,
}

impl DomainEvent for RuleAdded {
    fn event_type(&self) -> &'static str { "policy.rule_added" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

/// Policy was applied to target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApplied {
    pub metadata: EventMetadata,
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
}

impl DomainEvent for PolicyApplied {
    fn event_type(&self) -> &'static str { "policy.applied" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

// === Path Context Events ===

/// Path was switched
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSwitched {
    pub metadata: EventMetadata,
    pub site_id: String,
    pub app_class: String,
    pub from_path: String,
    pub to_path: String,
    pub reason: String,
    pub score_improvement: f32,
}

impl DomainEvent for PathSwitched {
    fn event_type(&self) -> &'static str { "path.switched" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

/// Path degradation detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathDegraded {
    pub metadata: EventMetadata,
    pub site_id: String,
    pub path: String,
    pub latency_us: u32,
    pub loss_permille: u16,
    pub predicted_congestion_ms: Option<u64>,
}

impl DomainEvent for PathDegraded {
    fn event_type(&self) -> &'static str { "path.degraded" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

// === DLP Context Events ===

/// Sensitive data violation detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationDetected {
    pub metadata: EventMetadata,
    pub classifier: String,
    pub severity: String,
    pub source: String,
    pub match_count: usize,
    pub action_taken: String,
}

impl DomainEvent for ViolationDetected {
    fn event_type(&self) -> &'static str { "dlp.violation_detected" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

// === Session Context Events ===

/// Session created
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCreated {
    pub metadata: EventMetadata,
    pub user_id: String,
    pub source_ip: String,
    pub device_trust: f32,
}

impl DomainEvent for SessionCreated {
    fn event_type(&self) -> &'static str { "session.created" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

/// Risk score updated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreUpdated {
    pub metadata: EventMetadata,
    pub previous_score: f32,
    pub new_score: f32,
    pub anomaly_factors: Vec<String>,
}

impl DomainEvent for RiskScoreUpdated {
    fn event_type(&self) -> &'static str { "session.risk_updated" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

/// MFA step-up required
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaRequired {
    pub metadata: EventMetadata,
    pub reason: String,
    pub risk_score: f32,
}

impl DomainEvent for MfaRequired {
    fn event_type(&self) -> &'static str { "session.mfa_required" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

/// Session blocked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBlocked {
    pub metadata: EventMetadata,
    pub reason: String,
    pub risk_score: f32,
}

impl DomainEvent for SessionBlocked {
    fn event_type(&self) -> &'static str { "session.blocked" }
    fn metadata(&self) -> &EventMetadata { &self.metadata }
}

// === Event Store ===

/// Event store for event sourcing
pub struct EventStore {
    events: Vec<Box<dyn DomainEvent>>,
}

impl EventStore {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn append(&mut self, event: Box<dyn DomainEvent>) {
        self.events.push(event);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

// Helpers
fn uuid_v4() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_created_event() {
        let event = PolicyCreated {
            metadata: EventMetadata::new("policy-1", "Policy", 1),
            policy_id: "policy-1".into(),
            default_action: "deny".into(),
        };

        assert_eq!(event.event_type(), "policy.created");
        assert_eq!(event.metadata().aggregate_id, "policy-1");
    }

    #[test]
    fn test_event_store() {
        let mut store = EventStore::new();
        
        store.append(Box::new(PolicyCreated {
            metadata: EventMetadata::new("p1", "Policy", 1),
            policy_id: "p1".into(),
            default_action: "allow".into(),
        }));

        store.append(Box::new(RuleAdded {
            metadata: EventMetadata::new("p1", "Policy", 2),
            rule_id: 1,
            priority: 100,
            action: "allow".into(),
        }));

        assert_eq!(store.len(), 2);
    }
}
