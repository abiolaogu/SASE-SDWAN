//! Policy Management Module
//!
//! Application-aware routing policies for SD-WAN.

use crate::{Result, SdwanError};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

/// Path preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathPreference {
    /// Best path based on metrics
    Best,
    /// Lowest latency
    LowLatency,
    /// Lowest cost
    LowCost,
    /// Highest bandwidth
    HighBandwidth,
    /// Load balanced
    LoadBalance,
    /// Specific WAN link
    Specific,
}

/// Egress action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressAction {
    /// Route via hub (PoP)
    RouteViaHub,
    /// Local internet breakout
    LocalBreakout,
    /// Direct to site
    DirectToSite,
    /// Drop traffic
    Drop,
}

/// Traffic match condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrafficMatch {
    /// Match by segment/VRF
    Segment(String),
    /// Match by application
    Application(String),
    /// Match by source IP
    SourceIp(String),
    /// Match by destination IP
    DestinationIp(String),
    /// Match by DSCP
    Dscp(u8),
    /// Match by port
    Port(u16),
    /// Match all
    All,
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    pub egress: EgressAction,
    pub path_preference: PathPreference,
    pub primary_wan: Option<String>,
    pub backup_wan: Option<String>,
    pub failover: bool,
}

/// SD-WAN Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdwanPolicy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u16,
    pub matches: Vec<TrafficMatch>,
    pub action: PolicyAction,
    pub enabled: bool,
    pub sites: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SdwanPolicy {
    /// Create new policy
    pub fn new(
        name: &str,
        priority: u16,
        matches: Vec<TrafficMatch>,
        action: PolicyAction,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            priority,
            matches,
            action,
            enabled: true,
            sites: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
    
    /// Check if traffic matches this policy
    pub fn matches_traffic(&self, segment: &str, app: Option<&str>) -> bool {
        self.matches.iter().any(|m| match m {
            TrafficMatch::Segment(s) => s == segment,
            TrafficMatch::Application(a) => app.map(|x| x == a).unwrap_or(false),
            TrafficMatch::All => true,
            _ => false,
        })
    }
}

/// Policy Manager
pub struct PolicyManager {
    policies: DashMap<String, SdwanPolicy>,
    /// Policies by site
    by_site: DashMap<String, Vec<String>>,
}

impl PolicyManager {
    /// Create new policy manager
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
            by_site: DashMap::new(),
        }
    }
    
    /// Create a new policy
    pub async fn create_policy(&self, policy: SdwanPolicy) -> Result<SdwanPolicy> {
        let policy_id = policy.id.clone();
        
        info!("Creating policy: {} (priority: {})", policy.name, policy.priority);
        
        // Index by sites
        for site_id in &policy.sites {
            self.by_site.entry(site_id.clone())
                .or_default()
                .push(policy_id.clone());
        }
        
        self.policies.insert(policy_id, policy.clone());
        Ok(policy)
    }
    
    /// Get policy by ID
    pub fn get_policy(&self, id: &str) -> Option<SdwanPolicy> {
        self.policies.get(id).map(|p| p.clone())
    }
    
    /// Get all policies
    pub fn list_policies(&self) -> Vec<SdwanPolicy> {
        self.policies.iter().map(|p| p.clone()).collect()
    }
    
    /// Get policies for a site (sorted by priority)
    pub fn get_site_policies(&self, site_id: &str) -> Vec<SdwanPolicy> {
        let mut policies: Vec<SdwanPolicy> = if let Some(policy_ids) = self.by_site.get(site_id) {
            policy_ids.iter()
                .filter_map(|id| self.get_policy(id))
                .collect()
        } else {
            // Return global policies (those with no specific sites)
            self.policies.iter()
                .filter(|p| p.sites.is_empty())
                .map(|p| p.clone())
                .collect()
        };
        
        policies.sort_by_key(|p| p.priority);
        policies
    }
    
    /// Match traffic to policy
    pub fn match_policy(&self, site_id: &str, segment: &str, app: Option<&str>) -> Option<SdwanPolicy> {
        self.get_site_policies(site_id)
            .into_iter()
            .find(|p| p.enabled && p.matches_traffic(segment, app))
    }
    
    /// Apply policy to sites
    pub async fn apply_to_sites(&self, policy_id: &str, site_ids: &[String]) -> Result<()> {
        if let Some(mut policy) = self.policies.get_mut(policy_id) {
            for site_id in site_ids {
                if !policy.sites.contains(site_id) {
                    policy.sites.push(site_id.clone());
                    
                    self.by_site.entry(site_id.clone())
                        .or_default()
                        .push(policy_id.to_string());
                }
            }
            policy.updated_at = Utc::now();
            info!("Applied policy {} to {} sites", policy_id, site_ids.len());
            Ok(())
        } else {
            Err(SdwanError::PolicyError(format!("Policy not found: {}", policy_id)))
        }
    }
    
    /// Update policy
    pub async fn update_policy(&self, id: &str, updates: PolicyUpdate) -> Result<()> {
        if let Some(mut policy) = self.policies.get_mut(id) {
            if let Some(enabled) = updates.enabled {
                policy.enabled = enabled;
            }
            if let Some(priority) = updates.priority {
                policy.priority = priority;
            }
            if let Some(action) = updates.action {
                policy.action = action;
            }
            policy.updated_at = Utc::now();
            Ok(())
        } else {
            Err(SdwanError::PolicyError(format!("Policy not found: {}", id)))
        }
    }
    
    /// Load default policies
    pub async fn load_defaults(&self) {
        // Corp segment - route via hub
        let corp_policy = SdwanPolicy::new(
            "corp-via-hub",
            100,
            vec![TrafficMatch::Segment("corp".to_string())],
            PolicyAction {
                egress: EgressAction::RouteViaHub,
                path_preference: PathPreference::LowLatency,
                primary_wan: Some("wan1".to_string()),
                backup_wan: Some("wan2".to_string()),
                failover: true,
            },
        );
        let _ = self.create_policy(corp_policy).await;
        
        // Guest segment - local breakout
        let guest_policy = SdwanPolicy::new(
            "guest-local-breakout",
            100,
            vec![TrafficMatch::Segment("guest".to_string())],
            PolicyAction {
                egress: EgressAction::LocalBreakout,
                path_preference: PathPreference::Best,
                primary_wan: Some("wan1".to_string()),
                backup_wan: None,
                failover: false,
            },
        );
        let _ = self.create_policy(guest_policy).await;
        
        // Voice traffic - low latency path
        let voice_policy = SdwanPolicy::new(
            "voice-priority",
            50,
            vec![TrafficMatch::Application("voice".to_string())],
            PolicyAction {
                egress: EgressAction::RouteViaHub,
                path_preference: PathPreference::LowLatency,
                primary_wan: Some("mpls".to_string()),
                backup_wan: Some("internet".to_string()),
                failover: true,
            },
        );
        let _ = self.create_policy(voice_policy).await;
        
        info!("Loaded {} default policies", self.policies.len());
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy update request
#[derive(Debug, Default)]
pub struct PolicyUpdate {
    pub enabled: Option<bool>,
    pub priority: Option<u16>,
    pub action: Option<PolicyAction>,
}
