//! Client Policy Engine
//!
//! Local policy enforcement for split tunneling and access control.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

pub struct PolicyEngine {
    policies: parking_lot::RwLock<Vec<Policy>>,
    split_tunnel_apps: parking_lot::RwLock<HashSet<String>>,
    split_tunnel_domains: parking_lot::RwLock<HashSet<String>>,
    blocked_apps: parking_lot::RwLock<HashSet<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub action: PolicyAction,
    pub priority: u32,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyType {
    /// Split tunnel specific apps/domains
    SplitTunnel(SplitTunnelPolicy),
    /// Block specific apps
    AppBlock(AppBlockPolicy),
    /// DNS policy
    Dns(DnsPolicy),
    /// Network access
    NetworkAccess(NetworkAccessPolicy),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitTunnelPolicy {
    pub mode: SplitTunnelMode,
    pub apps: Vec<String>,
    pub domains: Vec<String>,
    pub ip_ranges: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SplitTunnelMode {
    /// Tunnel everything except listed items
    Exclude,
    /// Only tunnel listed items
    Include,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppBlockPolicy {
    pub apps: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsPolicy {
    pub block_categories: Vec<String>,
    pub allow_list: Vec<String>,
    pub block_list: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkAccessPolicy {
    pub allowed_networks: Vec<String>,
    pub blocked_networks: Vec<String>,
    pub require_vpn_on_public: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Block,
    Log,
    Redirect,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: parking_lot::RwLock::new(Vec::new()),
            split_tunnel_apps: parking_lot::RwLock::new(HashSet::new()),
            split_tunnel_domains: parking_lot::RwLock::new(HashSet::new()),
            blocked_apps: parking_lot::RwLock::new(HashSet::new()),
        }
    }
    
    pub async fn apply(&self, policies: &[Policy]) -> Result<(), crate::ClientError> {
        let mut local_policies = self.policies.write();
        local_policies.clear();
        
        for policy in policies {
            if !policy.enabled { continue; }
            
            match &policy.policy_type {
                PolicyType::SplitTunnel(st) => {
                    self.apply_split_tunnel(st);
                }
                PolicyType::AppBlock(ab) => {
                    self.apply_app_block(ab);
                }
                PolicyType::Dns(dns) => {
                    self.apply_dns_policy(dns);
                }
                PolicyType::NetworkAccess(na) => {
                    self.apply_network_access(na);
                }
            }
            
            local_policies.push(policy.clone());
        }
        
        tracing::info!("Applied {} policies", local_policies.len());
        Ok(())
    }
    
    fn apply_split_tunnel(&self, policy: &SplitTunnelPolicy) {
        let mut apps = self.split_tunnel_apps.write();
        let mut domains = self.split_tunnel_domains.write();
        
        for app in &policy.apps {
            apps.insert(app.clone());
        }
        
        for domain in &policy.domains {
            domains.insert(domain.clone());
        }
    }
    
    fn apply_app_block(&self, policy: &AppBlockPolicy) {
        let mut blocked = self.blocked_apps.write();
        for app in &policy.apps {
            blocked.insert(app.clone());
        }
    }
    
    fn apply_dns_policy(&self, _policy: &DnsPolicy) {
        // DNS policy is handled by DnsManager
    }
    
    fn apply_network_access(&self, _policy: &NetworkAccessPolicy) {
        // Network access enforcement
    }
    
    /// Check if traffic should be split-tunneled (bypassed)
    pub fn should_bypass(&self, app: Option<&str>, domain: Option<&str>) -> bool {
        if let Some(app) = app {
            if self.split_tunnel_apps.read().contains(app) {
                return true;
            }
        }
        
        if let Some(domain) = domain {
            let domains = self.split_tunnel_domains.read();
            for pattern in domains.iter() {
                if domain.ends_with(pattern) || domain == pattern {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Check if app is blocked
    pub fn is_app_blocked(&self, app: &str) -> bool {
        self.blocked_apps.read().contains(app)
    }
    
    /// Get all policies
    pub fn policies(&self) -> Vec<Policy> {
        self.policies.read().clone()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self { Self::new() }
}
