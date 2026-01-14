//! Local Policy Engine

use crate::ClientError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;

/// Local policy engine (cached policies)
pub struct LocalPolicyEngine {
    policies: Arc<RwLock<Vec<Policy>>>,
    last_refresh: Arc<RwLock<u64>>,
    offline_mode: Arc<RwLock<bool>>,
}

impl LocalPolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(Vec::new())),
            last_refresh: Arc::new(RwLock::new(0)),
            offline_mode: Arc::new(RwLock::new(false)),
        }
    }

    /// Refresh policies from controller
    pub async fn refresh(&self) -> Result<(), ClientError> {
        tracing::info!("Refreshing policies from controller");
        
        // In production: fetch from controller API
        let policies = self.fetch_policies().await?;
        
        *self.policies.write() = policies;
        *self.last_refresh.write() = now();
        *self.offline_mode.write() = false;
        
        // Persist to local cache
        self.save_to_cache()?;
        
        Ok(())
    }

    /// Evaluate access decision
    pub fn evaluate(&self, request: &AccessRequest) -> AccessDecision {
        let policies = self.policies.read();
        
        for policy in policies.iter() {
            if !policy.enabled { continue; }
            
            if self.matches_policy(policy, request) {
                return match policy.action {
                    PolicyAction::Allow => AccessDecision::Allow,
                    PolicyAction::Deny => AccessDecision::Deny { reason: policy.name.clone() },
                    PolicyAction::Log => AccessDecision::Allow, // Log and allow
                };
            }
        }

        // Default deny
        AccessDecision::Deny { reason: "No matching policy".into() }
    }

    /// Load from local cache (offline mode)
    pub fn load_from_cache(&self) -> Result<(), ClientError> {
        tracing::info!("Loading policies from cache");
        
        // In production: load from encrypted local file
        *self.offline_mode.write() = true;
        
        Ok(())
    }

    fn matches_policy(&self, policy: &Policy, request: &AccessRequest) -> bool {
        // Check user
        if !policy.users.is_empty() && !policy.users.contains(&request.user_id) {
            return false;
        }

        // Check groups
        if !policy.groups.is_empty() {
            let has_group = request.groups.iter().any(|g| policy.groups.contains(g));
            if !has_group { return false; }
        }

        // Check destination
        if !policy.destinations.is_empty() {
            let matches_dest = policy.destinations.iter().any(|d| {
                request.destination.contains(d) || d == "*"
            });
            if !matches_dest { return false; }
        }

        // Check time restrictions
        if let Some(schedule) = &policy.schedule {
            if !self.is_within_schedule(schedule) {
                return false;
            }
        }

        true
    }

    fn is_within_schedule(&self, _schedule: &Schedule) -> bool {
        true // TODO: Implement schedule checking
    }

    async fn fetch_policies(&self) -> Result<Vec<Policy>, ClientError> {
        // Mock policies
        Ok(vec![
            Policy {
                id: "pol-1".into(),
                name: "Allow Internal Apps".into(),
                enabled: true,
                priority: 100,
                users: vec![],
                groups: vec!["employees".into()],
                destinations: vec!["*.internal.acme.com".into()],
                action: PolicyAction::Allow,
                schedule: None,
            },
            Policy {
                id: "pol-2".into(),
                name: "Block Social Media".into(),
                enabled: true,
                priority: 200,
                users: vec![],
                groups: vec![],
                destinations: vec!["*.facebook.com".into(), "*.tiktok.com".into()],
                action: PolicyAction::Deny,
                schedule: None,
            },
        ])
    }

    fn save_to_cache(&self) -> Result<(), ClientError> {
        // In production: encrypt and save to file
        Ok(())
    }
}

impl Default for LocalPolicyEngine {
    fn default() -> Self { Self::new() }
}

/// Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub destinations: Vec<String>,
    pub action: PolicyAction,
    pub schedule: Option<Schedule>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub days: Vec<u8>,      // 0-6 (Sunday-Saturday)
    pub start_hour: u8,
    pub end_hour: u8,
    pub timezone: String,
}

/// Access request
#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub user_id: String,
    pub groups: Vec<String>,
    pub destination: String,
    pub port: u16,
    pub protocol: String,
}

/// Access decision
#[derive(Debug, Clone)]
pub enum AccessDecision {
    Allow,
    Deny { reason: String },
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
