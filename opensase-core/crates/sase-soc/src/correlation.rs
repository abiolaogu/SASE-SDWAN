//! Event Correlation
//!
//! Correlate and deduplicate security events.

use crate::{SecurityEvent, SecurityAlert, Severity, AlertStatus, AlertEnrichment};
use std::collections::HashMap;

pub struct EventCorrelator {
    rules: dashmap::DashMap<String, CorrelationRule>,
    active_chains: dashmap::DashMap<String, EventChain>,
    dedup_window: dashmap::DashMap<String, DedupEntry>,
    stats: CorrelatorStats,
}

struct CorrelatorStats {
    events_correlated: std::sync::atomic::AtomicU64,
    events_deduplicated: std::sync::atomic::AtomicU64,
    alerts_generated: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub threshold: CorrelationThreshold,
    pub output_severity: Severity,
    pub mitre_attack: Vec<String>,
    pub enabled: bool,
}

#[derive(Clone)]
pub struct RuleCondition {
    pub field: String,
    pub operator: ConditionOp,
    pub value: String,
}

#[derive(Clone, Copy)]
pub enum ConditionOp {
    Equals, NotEquals, Contains, Regex, GreaterThan, LessThan,
}

#[derive(Clone)]
pub struct CorrelationThreshold {
    pub count: u64,
    pub time_window_secs: u64,
    pub group_by: Vec<String>,
}

#[derive(Clone)]
struct EventChain {
    rule_id: String,
    group_key: String,
    events: Vec<String>,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
}

struct DedupEntry {
    event_hash: String,
    count: u64,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
}

impl EventCorrelator {
    pub fn new() -> Self {
        let correlator = Self {
            rules: dashmap::DashMap::new(),
            active_chains: dashmap::DashMap::new(),
            dedup_window: dashmap::DashMap::new(),
            stats: CorrelatorStats {
                events_correlated: std::sync::atomic::AtomicU64::new(0),
                events_deduplicated: std::sync::atomic::AtomicU64::new(0),
                alerts_generated: std::sync::atomic::AtomicU64::new(0),
            },
        };
        correlator.load_default_rules();
        correlator
    }
    
    fn load_default_rules(&self) {
        // Brute force rule
        self.rules.insert("brute-force".to_string(), CorrelationRule {
            id: "brute-force".to_string(),
            name: "Brute Force Attack".to_string(),
            description: "Multiple failed logins from same source".to_string(),
            conditions: vec![
                RuleCondition {
                    field: "event_type".to_string(),
                    operator: ConditionOp::Equals,
                    value: "AuthenticationFailure".to_string(),
                },
            ],
            threshold: CorrelationThreshold {
                count: 5,
                time_window_secs: 300,
                group_by: vec!["source.ip".to_string()],
            },
            output_severity: Severity::High,
            mitre_attack: vec!["T1110".to_string()],
            enabled: true,
        });
        
        // Port scan rule
        self.rules.insert("port-scan".to_string(), CorrelationRule {
            id: "port-scan".to_string(),
            name: "Port Scan Detection".to_string(),
            description: "Multiple connection attempts to different ports".to_string(),
            conditions: vec![
                RuleCondition {
                    field: "event_type".to_string(),
                    operator: ConditionOp::Equals,
                    value: "PortScan".to_string(),
                },
            ],
            threshold: CorrelationThreshold {
                count: 20,
                time_window_secs: 60,
                group_by: vec!["source.ip".to_string()],
            },
            output_severity: Severity::Medium,
            mitre_attack: vec!["T1046".to_string()],
            enabled: true,
        });
        
        // Data exfiltration rule
        self.rules.insert("data-exfil".to_string(), CorrelationRule {
            id: "data-exfil".to_string(),
            name: "Data Exfiltration".to_string(),
            description: "Large data transfer to external destination".to_string(),
            conditions: vec![
                RuleCondition {
                    field: "event_type".to_string(),
                    operator: ConditionOp::Equals,
                    value: "DataExfiltration".to_string(),
                },
            ],
            threshold: CorrelationThreshold {
                count: 3,
                time_window_secs: 3600,
                group_by: vec!["source.ip".to_string(), "destination.ip".to_string()],
            },
            output_severity: Severity::Critical,
            mitre_attack: vec!["T1041".to_string()],
            enabled: true,
        });
    }
    
    pub async fn process(&self, event: &SecurityEvent) -> Option<SecurityAlert> {
        // Deduplication
        let event_hash = self.compute_hash(event);
        if self.is_duplicate(&event_hash) {
            self.stats.events_deduplicated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        
        // Check correlation rules
        for rule in self.rules.iter() {
            if !rule.enabled { continue; }
            if !self.matches_conditions(&rule, event) { continue; }
            
            let group_key = self.compute_group_key(&rule, event);
            let chain_key = format!("{}:{}", rule.id, group_key);
            
            // Update or create chain
            let should_alert = {
                let mut chain = self.active_chains.entry(chain_key.clone()).or_insert_with(|| EventChain {
                    rule_id: rule.id.clone(),
                    group_key: group_key.clone(),
                    events: vec![],
                    first_seen: chrono::Utc::now(),
                    last_seen: chrono::Utc::now(),
                });
                
                chain.events.push(event.id.clone());
                chain.last_seen = chrono::Utc::now();
                
                // Check threshold
                let window_start = chrono::Utc::now() - chrono::Duration::seconds(rule.threshold.time_window_secs as i64);
                if chain.first_seen >= window_start && chain.events.len() as u64 >= rule.threshold.count {
                    true
                } else {
                    false
                }
            };
            
            if should_alert {
                self.stats.alerts_generated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                
                // Get event IDs from chain
                let event_ids = self.active_chains.get(&chain_key)
                    .map(|c| c.events.clone())
                    .unwrap_or_default();
                
                // Clear chain
                self.active_chains.remove(&chain_key);
                
                return Some(SecurityAlert {
                    id: uuid::Uuid::new_v4().to_string(),
                    events: event_ids,
                    alert_type: rule.name.clone(),
                    severity: rule.output_severity,
                    status: AlertStatus::New,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    assigned_to: None,
                    mitre_tactics: vec![],
                    mitre_techniques: rule.mitre_attack.clone(),
                    enrichment: AlertEnrichment::default(),
                    case_id: None,
                });
            }
        }
        
        self.stats.events_correlated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }
    
    fn compute_hash(&self, event: &SecurityEvent) -> String {
        use sha2::{Sha256, Digest};
        let data = format!("{:?}{}{}",
            event.event_type,
            event.source.ip.as_deref().unwrap_or(""),
            event.description
        );
        let hash = Sha256::digest(data.as_bytes());
        hex::encode(&hash[..8])
    }
    
    fn is_duplicate(&self, hash: &str) -> bool {
        let now = chrono::Utc::now();
        let window = chrono::Duration::minutes(5);
        
        if let Some(mut entry) = self.dedup_window.get_mut(hash) {
            if now - entry.first_seen < window {
                entry.count += 1;
                entry.last_seen = now;
                return true;
            }
        }
        
        self.dedup_window.insert(hash.to_string(), DedupEntry {
            event_hash: hash.to_string(),
            count: 1,
            first_seen: now,
            last_seen: now,
        });
        false
    }
    
    fn matches_conditions(&self, rule: &CorrelationRule, event: &SecurityEvent) -> bool {
        for cond in &rule.conditions {
            let value = self.get_field_value(event, &cond.field);
            let matches = match cond.operator {
                ConditionOp::Equals => value == Some(cond.value.clone()),
                ConditionOp::NotEquals => value != Some(cond.value.clone()),
                ConditionOp::Contains => value.map(|v| v.contains(&cond.value)).unwrap_or(false),
                _ => true,
            };
            if !matches { return false; }
        }
        true
    }
    
    fn get_field_value(&self, event: &SecurityEvent, field: &str) -> Option<String> {
        match field {
            "event_type" => Some(format!("{:?}", event.event_type)),
            "severity" => Some(format!("{:?}", event.severity)),
            "source.ip" => event.source.ip.clone(),
            "source.host" => event.source.host.clone(),
            _ => None,
        }
    }
    
    fn compute_group_key(&self, rule: &CorrelationRule, event: &SecurityEvent) -> String {
        let parts: Vec<String> = rule.threshold.group_by.iter()
            .filter_map(|f| self.get_field_value(event, f))
            .collect();
        parts.join(":")
    }
    
    pub fn register_rule(&self, rule: CorrelationRule) {
        self.rules.insert(rule.id.clone(), rule);
    }
    
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now();
        
        // Cleanup dedup window
        let expired_dedup: Vec<String> = self.dedup_window.iter()
            .filter(|e| now - e.first_seen > chrono::Duration::minutes(10))
            .map(|e| e.event_hash.clone())
            .collect();
        for key in expired_dedup {
            self.dedup_window.remove(&key);
        }
        
        // Cleanup chains
        let expired_chains: Vec<String> = self.active_chains.iter()
            .filter(|c| now - c.last_seen > chrono::Duration::hours(1))
            .map(|c| format!("{}:{}", c.rule_id, c.group_key))
            .collect();
        for key in expired_chains {
            self.active_chains.remove(&key);
        }
    }
}

impl Default for EventCorrelator {
    fn default() -> Self { Self::new() }
}
