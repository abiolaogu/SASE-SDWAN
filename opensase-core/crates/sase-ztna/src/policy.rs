//! Policy Engine
//!
//! Zero Trust policy evaluation with ABAC and RBAC support.

use crate::{AccessRequest, AccessDecision, Decision, AccessCondition, DataSensitivity};
use std::collections::HashMap;

/// Policy decision engine
pub struct PolicyEngine {
    /// Policies
    policies: dashmap::DashMap<String, Policy>,
    /// Role definitions
    roles: dashmap::DashMap<String, Role>,
    /// Resource policies
    resource_policies: dashmap::DashMap<String, ResourcePolicy>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub priority: i32,
    pub enabled: bool,
    pub conditions: Vec<PolicyCondition>,
    pub effect: PolicyEffect,
    pub access_conditions: Vec<AccessCondition>,
}

#[derive(Debug, Clone)]
pub enum PolicyCondition {
    // Identity conditions
    HasRole(String),
    InGroup(String),
    HasAttribute { key: String, value: String },
    
    // Device conditions
    DeviceManaged,
    DeviceCompliant,
    MinTrustLevel(crate::TrustLevel),
    
    // Context conditions
    FromNetwork(crate::NetworkType),
    FromCountry(String),
    DuringHours { start: u8, end: u8 },
    RiskScoreBelow(f64),
    
    // Resource conditions
    ResourceType(crate::ResourceType),
    ResourceSensitivity(DataSensitivity),
    ResourceTag { key: String, value: String },
    
    // Logical
    And(Vec<PolicyCondition>),
    Or(Vec<PolicyCondition>),
    Not(Box<PolicyCondition>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
    Challenge,
    Audit,
}

#[derive(Debug, Clone)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub permissions: Vec<Permission>,
    pub inherits: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Permission {
    pub resource_type: crate::ResourceType,
    pub actions: Vec<crate::AccessAction>,
    pub conditions: Vec<PolicyCondition>,
}

#[derive(Debug, Clone)]
pub struct ResourcePolicy {
    pub resource_id: String,
    pub allowed_roles: Vec<String>,
    pub allowed_groups: Vec<String>,
    pub allowed_users: Vec<String>,
    pub conditions: Vec<PolicyCondition>,
    pub access_conditions: Vec<AccessCondition>,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reasons: Vec<String>,
    pub conditions: Vec<AccessCondition>,
    pub matching_policies: Vec<String>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let engine = Self {
            policies: dashmap::DashMap::new(),
            roles: dashmap::DashMap::new(),
            resource_policies: dashmap::DashMap::new(),
        };
        
        // Add default policies
        engine.add_default_policies();
        
        engine
    }
    
    fn add_default_policies(&self) {
        // Deny untrusted devices
        self.add_policy(Policy {
            id: "deny-untrusted-devices".to_string(),
            name: "Deny Untrusted Devices".to_string(),
            description: "Block access from untrusted devices".to_string(),
            priority: 100,
            enabled: true,
            conditions: vec![
                PolicyCondition::Not(Box::new(
                    PolicyCondition::MinTrustLevel(crate::TrustLevel::Low)
                )),
            ],
            effect: PolicyEffect::Deny,
            access_conditions: vec![],
        });
        
        // Require MFA for sensitive data
        self.add_policy(Policy {
            id: "mfa-for-sensitive".to_string(),
            name: "MFA for Sensitive Resources".to_string(),
            description: "Require MFA for confidential and restricted data".to_string(),
            priority: 50,
            enabled: true,
            conditions: vec![
                PolicyCondition::Or(vec![
                    PolicyCondition::ResourceSensitivity(DataSensitivity::Confidential),
                    PolicyCondition::ResourceSensitivity(DataSensitivity::Restricted),
                ]),
            ],
            effect: PolicyEffect::Allow,
            access_conditions: vec![AccessCondition::RequireMfa],
        });
        
        // Block high risk access
        self.add_policy(Policy {
            id: "block-high-risk".to_string(),
            name: "Block High Risk Access".to_string(),
            description: "Block access when risk score is too high".to_string(),
            priority: 90,
            enabled: true,
            conditions: vec![
                PolicyCondition::Not(Box::new(
                    PolicyCondition::RiskScoreBelow(80.0)
                )),
            ],
            effect: PolicyEffect::Deny,
            access_conditions: vec![],
        });
    }
    
    /// Evaluate access request
    pub async fn evaluate(&self, request: &AccessRequest) -> PolicyDecision {
        let mut matching_policies = Vec::new();
        let mut all_conditions = Vec::new();
        let mut decision = Decision::Allow;
        let mut reasons = Vec::new();
        
        // Get sorted policies by priority (higher first)
        let mut policies: Vec<_> = self.policies.iter()
            .filter(|p| p.enabled)
            .map(|p| p.clone())
            .collect();
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Evaluate each policy
        for policy in policies {
            if self.evaluate_conditions(&policy.conditions, request) {
                matching_policies.push(policy.id.clone());
                
                match policy.effect {
                    PolicyEffect::Deny => {
                        decision = Decision::Deny;
                        reasons.push(format!("Denied by policy: {}", policy.name));
                        // Short-circuit on deny
                        break;
                    }
                    PolicyEffect::Challenge => {
                        if decision != Decision::Deny {
                            decision = Decision::Challenge;
                            reasons.push(format!("Challenge required by: {}", policy.name));
                        }
                    }
                    PolicyEffect::Allow => {
                        all_conditions.extend(policy.access_conditions.clone());
                        reasons.push(format!("Allowed by: {}", policy.name));
                    }
                    PolicyEffect::Audit => {
                        // Just log, don't affect decision
                        tracing::info!("Audit policy matched: {}", policy.name);
                    }
                }
            }
        }
        
        // Check resource-specific policy
        if let Some(resource_policy) = self.resource_policies.get(&request.resource.id) {
            let rp_result = self.evaluate_resource_policy(&resource_policy, request);
            if !rp_result.allowed {
                decision = Decision::Deny;
                reasons.push("Denied by resource policy".to_string());
            } else {
                all_conditions.extend(resource_policy.access_conditions.clone());
            }
        }
        
        // Check RBAC
        if decision != Decision::Deny {
            let rbac_result = self.check_rbac(request);
            if !rbac_result {
                decision = Decision::Deny;
                reasons.push("No role grants access".to_string());
            }
        }
        
        PolicyDecision {
            decision,
            reasons,
            conditions: all_conditions,
            matching_policies,
        }
    }
    
    fn evaluate_conditions(&self, conditions: &[PolicyCondition], request: &AccessRequest) -> bool {
        conditions.iter().all(|c| self.evaluate_condition(c, request))
    }
    
    fn evaluate_condition(&self, condition: &PolicyCondition, request: &AccessRequest) -> bool {
        match condition {
            PolicyCondition::HasRole(role) => request.identity.roles.contains(role),
            PolicyCondition::InGroup(group) => request.identity.groups.contains(group),
            PolicyCondition::HasAttribute { key, value } => {
                request.identity.attributes.get(key) == Some(value)
            }
            PolicyCondition::DeviceManaged => request.device.managed,
            PolicyCondition::DeviceCompliant => request.device.compliant,
            PolicyCondition::MinTrustLevel(min) => request.device.trust_level >= *min,
            PolicyCondition::FromNetwork(network) => request.context.network_type == *network,
            PolicyCondition::FromCountry(country) => {
                request.context.geo_location.as_ref()
                    .map(|g| &g.country == country)
                    .unwrap_or(false)
            }
            PolicyCondition::DuringHours { start, end } => {
                let hour = request.context.time_of_access.time().hour() as u8;
                hour >= *start && hour <= *end
            }
            PolicyCondition::RiskScoreBelow(max) => request.context.risk_score < *max,
            PolicyCondition::ResourceType(rt) => request.resource.resource_type == *rt,
            PolicyCondition::ResourceSensitivity(s) => request.resource.sensitivity == *s,
            PolicyCondition::ResourceTag { key, value } => {
                request.resource.tags.get(key) == Some(value)
            }
            PolicyCondition::And(conditions) => {
                conditions.iter().all(|c| self.evaluate_condition(c, request))
            }
            PolicyCondition::Or(conditions) => {
                conditions.iter().any(|c| self.evaluate_condition(c, request))
            }
            PolicyCondition::Not(condition) => {
                !self.evaluate_condition(condition, request)
            }
        }
    }
    
    fn evaluate_resource_policy(&self, policy: &ResourcePolicy, request: &AccessRequest) -> ResourcePolicyResult {
        // Check user
        if policy.allowed_users.contains(&request.identity.user_id) {
            return ResourcePolicyResult { allowed: true };
        }
        
        // Check groups
        for group in &request.identity.groups {
            if policy.allowed_groups.contains(group) {
                return ResourcePolicyResult { allowed: true };
            }
        }
        
        // Check roles
        for role in &request.identity.roles {
            if policy.allowed_roles.contains(role) {
                return ResourcePolicyResult { allowed: true };
            }
        }
        
        ResourcePolicyResult { allowed: false }
    }
    
    fn check_rbac(&self, request: &AccessRequest) -> bool {
        for role_name in &request.identity.roles {
            if let Some(role) = self.roles.get(role_name) {
                if self.role_grants_access(&role, request) {
                    return true;
                }
            }
        }
        
        // No role grants access - default deny
        false
    }
    
    fn role_grants_access(&self, role: &Role, request: &AccessRequest) -> bool {
        for permission in &role.permissions {
            if permission.resource_type == request.resource.resource_type &&
               permission.actions.contains(&request.action) {
                if self.evaluate_conditions(&permission.conditions, request) {
                    return true;
                }
            }
        }
        
        // Check inherited roles
        for inherited in &role.inherits {
            if let Some(parent_role) = self.roles.get(inherited) {
                if self.role_grants_access(&parent_role, request) {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Add policy
    pub fn add_policy(&self, policy: Policy) {
        self.policies.insert(policy.id.clone(), policy);
    }
    
    /// Add role
    pub fn add_role(&self, role: Role) {
        self.roles.insert(role.id.clone(), role);
    }
    
    /// Add resource policy
    pub fn add_resource_policy(&self, policy: ResourcePolicy) {
        self.resource_policies.insert(policy.resource_id.clone(), policy);
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

struct ResourcePolicyResult {
    allowed: bool,
}

use chrono::Timelike;
