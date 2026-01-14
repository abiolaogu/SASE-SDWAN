//! OpenSASE VPP Policy Manager
//!
//! Rust API for dynamic policy management via VPP API.
//! Supports runtime policy updates without service interruption.

use dashmap::DashMap;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;

/// Policy ID type
pub type PolicyId = u32;

/// Policy errors
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("VPP API error: {0}")]
    VppApi(String),

    #[error("Policy not found: {0}")]
    PolicyNotFound(PolicyId),

    #[error("Invalid policy configuration")]
    InvalidConfig,
}

pub type Result<T> = std::result::Result<T, PolicyError>;

/// Policy action
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
    Log,
    RateLimit,
    Redirect,
    Encrypt,
    InspectDlp,
}

impl PolicyAction {
    pub fn to_vpp_action(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Deny => 1,
            Self::Log => 2,
            Self::RateLimit => 3,
            Self::Redirect => 4,
            Self::Encrypt => 5,
            Self::InspectDlp => 6,
        }
    }
}

/// QoS class
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum QosClass {
    Realtime = 0,
    BusinessCritical = 1,
    Default = 2,
    Bulk = 3,
    Scavenger = 4,
}

/// Policy match criteria
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyMatch {
    /// Source IP prefix (None = any)
    pub src_prefix: Option<IpNetwork>,

    /// Destination IP prefix (None = any)
    pub dst_prefix: Option<IpNetwork>,

    /// Source port range (None = any)
    pub src_port_range: Option<(u16, u16)>,

    /// Destination port range (None = any)
    pub dst_port_range: Option<(u16, u16)>,

    /// Protocol (None = any)
    pub protocol: Option<u8>,

    /// Tenant ID (None = global)
    pub tenant_id: Option<u32>,
}

impl Default for PolicyMatch {
    fn default() -> Self {
        Self {
            src_prefix: None,
            dst_prefix: None,
            src_port_range: None,
            dst_port_range: None,
            protocol: None,
            tenant_id: None,
        }
    }
}

/// Policy rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique policy ID
    pub id: PolicyId,

    /// Priority (lower = higher priority)
    pub priority: u32,

    /// Match criteria
    pub match_criteria: PolicyMatch,

    /// Action to take
    pub action: PolicyAction,

    /// QoS class to apply
    pub qos_class: Option<QosClass>,

    /// Rate limit in Kbps (if action is RateLimit)
    pub rate_limit_kbps: Option<u32>,

    /// Enable logging
    pub log_enabled: bool,
}

/// Policy statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyStats {
    pub hits: u64,
    pub bytes: u64,
    pub last_hit: Option<std::time::SystemTime>,
}

/// VPP Policy Manager
pub struct VppPolicyManager {
    /// Active policies
    policies: DashMap<PolicyId, PolicyRule>,

    /// Policy statistics
    stats: DashMap<PolicyId, PolicyStats>,

    /// Next policy ID
    next_id: AtomicU32,

    /// VPP CLI socket path
    vpp_socket: String,
}

impl VppPolicyManager {
    /// Create a new policy manager
    pub fn new(vpp_socket: &str) -> Self {
        Self {
            policies: DashMap::new(),
            stats: DashMap::new(),
            next_id: AtomicU32::new(1),
            vpp_socket: vpp_socket.to_string(),
        }
    }

    /// Add a policy rule
    pub async fn add_policy(&self, mut rule: PolicyRule) -> Result<PolicyId> {
        // Assign ID if not set
        if rule.id == 0 {
            rule.id = self.next_id.fetch_add(1, Ordering::SeqCst);
        }

        let policy_id = rule.id;

        // Send to VPP via CLI
        self.send_policy_to_vpp(&rule).await?;

        // Store locally
        self.policies.insert(policy_id, rule);
        self.stats.insert(policy_id, PolicyStats::default());

        tracing::info!(policy_id = policy_id, "Policy added");

        Ok(policy_id)
    }

    /// Remove a policy rule
    pub async fn remove_policy(&self, policy_id: PolicyId) -> Result<()> {
        // Remove from VPP
        self.remove_policy_from_vpp(policy_id).await?;

        // Remove local state
        self.policies.remove(&policy_id);
        self.stats.remove(&policy_id);

        tracing::info!(policy_id = policy_id, "Policy removed");

        Ok(())
    }

    /// Update a policy rule
    pub async fn update_policy(&self, rule: PolicyRule) -> Result<()> {
        let policy_id = rule.id;

        if !self.policies.contains_key(&policy_id) {
            return Err(PolicyError::PolicyNotFound(policy_id));
        }

        // Update in VPP (remove + add)
        self.remove_policy_from_vpp(policy_id).await.ok();
        self.send_policy_to_vpp(&rule).await?;

        // Update local
        self.policies.insert(policy_id, rule);

        Ok(())
    }

    /// Get policy statistics
    pub async fn get_policy_stats(&self, policy_id: PolicyId) -> Result<PolicyStats> {
        self.stats
            .get(&policy_id)
            .map(|r| r.clone())
            .ok_or(PolicyError::PolicyNotFound(policy_id))
    }

    /// List all policies
    pub fn list_policies(&self) -> Vec<PolicyRule> {
        self.policies.iter().map(|r| r.value().clone()).collect()
    }

    /// Get policy by ID
    pub fn get_policy(&self, policy_id: PolicyId) -> Option<PolicyRule> {
        self.policies.get(&policy_id).map(|r| r.clone())
    }

    /// Send policy to VPP via CLI
    async fn send_policy_to_vpp(&self, rule: &PolicyRule) -> Result<()> {
        let mut cmd = format!(
            "opensase policy add id {} priority {}",
            rule.id, rule.priority
        );

        if let Some(ref src) = rule.match_criteria.src_prefix {
            cmd.push_str(&format!(" src {}", src));
        } else {
            cmd.push_str(" src any");
        }

        if let Some(ref dst) = rule.match_criteria.dst_prefix {
            cmd.push_str(&format!(" dst {}", dst));
        } else {
            cmd.push_str(" dst any");
        }

        if let Some((min, max)) = rule.match_criteria.dst_port_range {
            if min == max {
                cmd.push_str(&format!(" port {}", min));
            } else {
                cmd.push_str(&format!(" port {}-{}", min, max));
            }
        }

        if let Some(proto) = rule.match_criteria.protocol {
            cmd.push_str(&format!(" protocol {}", proto));
        }

        if let Some(tenant) = rule.match_criteria.tenant_id {
            cmd.push_str(&format!(" tenant {}", tenant));
        }

        cmd.push_str(&format!(" action {:?}", rule.action).to_lowercase());

        if let Some(qos) = rule.qos_class {
            cmd.push_str(&format!(" qos {}", qos as u8));
        }

        if let Some(rate) = rule.rate_limit_kbps {
            cmd.push_str(&format!(" rate-limit {}", rate));
        }

        if rule.log_enabled {
            cmd.push_str(" log");
        }

        tracing::debug!(cmd = %cmd, "Sending policy to VPP");

        // TODO: Actually send via VPP CLI socket
        // self.execute_vpp_cli(&cmd).await?;

        Ok(())
    }

    /// Remove policy from VPP
    async fn remove_policy_from_vpp(&self, policy_id: PolicyId) -> Result<()> {
        let cmd = format!("opensase policy del id {}", policy_id);
        tracing::debug!(cmd = %cmd, "Removing policy from VPP");

        // TODO: Actually send via VPP CLI socket
        // self.execute_vpp_cli(&cmd).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_policy() {
        let manager = VppPolicyManager::new("/run/vpp/cli.sock");

        let rule = PolicyRule {
            id: 0,
            priority: 100,
            match_criteria: PolicyMatch {
                src_prefix: Some("10.0.0.0/8".parse().unwrap()),
                dst_prefix: None,
                ..Default::default()
            },
            action: PolicyAction::Allow,
            qos_class: Some(QosClass::Default),
            rate_limit_kbps: None,
            log_enabled: false,
        };

        let policy_id = manager.add_policy(rule).await.unwrap();
        assert!(policy_id > 0);

        let policies = manager.list_policies();
        assert_eq!(policies.len(), 1);
    }
}
