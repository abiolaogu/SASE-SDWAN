//! Policy Engine - Policy evaluation and storage

use crate::authz::User;
use chrono::{DateTime, Utc, Timelike};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

/// Policy decision
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Allow the request
    Allow,
    /// Deny with reason
    Deny(String),
    /// Require MFA
    RequireMFA,
    /// Require step-up authentication
    StepUp(String),
}

/// Context for policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub user: User,
    pub groups: Vec<String>,
    pub source_ip: Option<String>,
    pub destination: String,
    pub path: String,
    pub method: String,
    pub time: DateTime<Utc>,
    pub device_posture: Option<super::server::DevicePosture>,
    pub headers: HashMap<String, String>,
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// User is in specified groups
    InGroups(Vec<String>),
    /// Request matches path pattern
    PathPattern(String),
    /// Request uses specified methods
    Methods(Vec<String>),
    /// Source IP in CIDR range
    SourceIp(String),
    /// Time within range (hours)
    TimeRange { start: u8, end: u8 },
    /// Device posture score minimum
    DevicePostureMin(u32),
    /// MFA verified
    MfaVerified,
    /// All conditions must match
    All(Vec<PolicyCondition>),
    /// Any condition must match
    Any(Vec<PolicyCondition>),
    /// Negate condition
    Not(Box<PolicyCondition>),
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny(String),
    RequireMFA,
    StepUp(String),
}

/// Single policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Conditions to match
    pub conditions: Vec<PolicyCondition>,
    /// Action when matched
    pub action: PolicyAction,
    /// Is policy enabled
    pub enabled: bool,
    /// Tenant ID (for multi-tenancy)
    pub tenant_id: Option<String>,
}

impl Policy {
    /// Evaluate policy against context
    pub fn evaluate(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        if !self.enabled {
            return None;
        }
        
        // Check tenant
        if let Some(ref tenant) = self.tenant_id {
            if &ctx.user.tenant_id != tenant {
                return None;
            }
        }
        
        // All conditions must match
        let matches = self.conditions.iter().all(|c| c.matches(ctx));
        
        if matches {
            Some(match &self.action {
                PolicyAction::Allow => PolicyDecision::Allow,
                PolicyAction::Deny(reason) => PolicyDecision::Deny(reason.clone()),
                PolicyAction::RequireMFA => PolicyDecision::RequireMFA,
                PolicyAction::StepUp(level) => PolicyDecision::StepUp(level.clone()),
            })
        } else {
            None
        }
    }
}

impl PolicyCondition {
    /// Check if condition matches context
    pub fn matches(&self, ctx: &PolicyContext) -> bool {
        match self {
            PolicyCondition::InGroups(groups) => {
                groups.iter().any(|g| ctx.groups.contains(g))
            }
            PolicyCondition::PathPattern(pattern) => {
                path_matches(&ctx.path, pattern)
            }
            PolicyCondition::Methods(methods) => {
                methods.iter().any(|m| m.eq_ignore_ascii_case(&ctx.method))
            }
            PolicyCondition::SourceIp(cidr) => {
                if let Some(ref ip) = ctx.source_ip {
                    ip_in_cidr(ip, cidr)
                } else {
                    false
                }
            }
            PolicyCondition::TimeRange { start, end } => {
                let hour = ctx.time.hour() as u8;
                if start <= end {
                    hour >= *start && hour < *end
                } else {
                    hour >= *start || hour < *end
                }
            }
            PolicyCondition::DevicePostureMin(min_score) => {
                ctx.device_posture.as_ref()
                    .map(|p| p.score >= *min_score)
                    .unwrap_or(false)
            }
            PolicyCondition::MfaVerified => {
                ctx.headers.get("x-mfa-verified")
                    .map(|v| v == "true")
                    .unwrap_or(false)
            }
            PolicyCondition::All(conditions) => {
                conditions.iter().all(|c| c.matches(ctx))
            }
            PolicyCondition::Any(conditions) => {
                conditions.iter().any(|c| c.matches(ctx))
            }
            PolicyCondition::Not(condition) => {
                !condition.matches(ctx)
            }
        }
    }
}

/// Policy store
pub struct PolicyStore {
    /// Policies by ID
    policies: DashMap<String, Policy>,
    /// Sorted policy IDs by priority
    sorted_ids: tokio::sync::RwLock<Vec<String>>,
}

impl PolicyStore {
    /// Create new policy store
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
            sorted_ids: tokio::sync::RwLock::new(Vec::new()),
        }
    }
    
    /// Add policy
    pub async fn add_policy(&self, policy: Policy) {
        self.policies.insert(policy.id.clone(), policy);
        self.sort_policies().await;
    }
    
    /// Remove policy
    pub async fn remove_policy(&self, id: &str) {
        self.policies.remove(id);
        self.sort_policies().await;
    }
    
    /// Sort policies by priority
    async fn sort_policies(&self) {
        let mut ids: Vec<_> = self.policies.iter()
            .map(|p| (p.id.clone(), p.priority))
            .collect();
        ids.sort_by_key(|(_, p)| *p);
        
        let mut sorted = self.sorted_ids.write().await;
        *sorted = ids.into_iter().map(|(id, _)| id).collect();
    }
    
    /// Evaluate all policies
    pub async fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecision {
        let sorted = self.sorted_ids.read().await;
        
        for id in sorted.iter() {
            if let Some(policy) = self.policies.get(id) {
                if let Some(decision) = policy.evaluate(ctx) {
                    debug!("Policy {} matched: {:?}", policy.name, decision);
                    return decision;
                }
            }
        }
        
        // Default deny
        PolicyDecision::Deny("No matching policy".to_string())
    }
    
    /// Load default policies
    pub async fn load_defaults(&self) {
        // Admin access - require MFA and admin group
        self.add_policy(Policy {
            id: "admin-access".to_string(),
            name: "Admin Access".to_string(),
            priority: 10,
            conditions: vec![
                PolicyCondition::PathPattern("/admin/*".to_string()),
                PolicyCondition::InGroups(vec!["admin".to_string()]),
                PolicyCondition::MfaVerified,
            ],
            action: PolicyAction::Allow,
            enabled: true,
            tenant_id: None,
        }).await;
        
        // Admin without MFA - require step-up
        self.add_policy(Policy {
            id: "admin-stepup".to_string(),
            name: "Admin Step-Up".to_string(),
            priority: 15,
            conditions: vec![
                PolicyCondition::PathPattern("/admin/*".to_string()),
                PolicyCondition::InGroups(vec!["admin".to_string()]),
                PolicyCondition::Not(Box::new(PolicyCondition::MfaVerified)),
            ],
            action: PolicyAction::RequireMFA,
            enabled: true,
            tenant_id: None,
        }).await;
        
        // API read access
        self.add_policy(Policy {
            id: "api-read".to_string(),
            name: "API Read Access".to_string(),
            priority: 50,
            conditions: vec![
                PolicyCondition::PathPattern("/api/*".to_string()),
                PolicyCondition::Methods(vec!["GET".to_string()]),
            ],
            action: PolicyAction::Allow,
            enabled: true,
            tenant_id: None,
        }).await;
        
        // API write access - require device posture
        self.add_policy(Policy {
            id: "api-write".to_string(),
            name: "API Write Access".to_string(),
            priority: 45,
            conditions: vec![
                PolicyCondition::PathPattern("/api/*".to_string()),
                PolicyCondition::Methods(vec!["POST".to_string(), "PUT".to_string(), "DELETE".to_string()]),
                PolicyCondition::DevicePostureMin(70),
            ],
            action: PolicyAction::Allow,
            enabled: true,
            tenant_id: None,
        }).await;
        
        // Health endpoints - always allow
        self.add_policy(Policy {
            id: "health".to_string(),
            name: "Health Endpoints".to_string(),
            priority: 1,
            conditions: vec![
                PolicyCondition::Any(vec![
                    PolicyCondition::PathPattern("/health".to_string()),
                    PolicyCondition::PathPattern("/ready".to_string()),
                    PolicyCondition::PathPattern("/metrics".to_string()),
                ]),
            ],
            action: PolicyAction::Allow,
            enabled: true,
            tenant_id: None,
        }).await;
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple glob-style path matching
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        path.starts_with(prefix)
    } else if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

/// Simple IP in CIDR check
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    // Simplified - in production use proper CIDR parsing
    if cidr.contains('/') {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() == 2 {
            let network = parts[0];
            return ip.starts_with(&network[..network.len().saturating_sub(2)]);
        }
    }
    ip == cidr
}
