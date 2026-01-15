//! Tenant Entitlements and Feature Gating
//!
//! Adapted from BSS-OSS subscription management patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// SASE features that can be entitled
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SaseFeature {
    ZeroTrustAccess,
    SecureWebGateway,
    CloudAccessSecurityBroker,
    DataLossPrevention,
    RemoteBrowserIsolation,
    AdvancedThreatProtection,
    SdWanOptimization,
    FirewallAsService,
    DnsSecurityFilter,
    SslInspection,
}

impl SaseFeature {
    pub fn all() -> HashSet<SaseFeature> {
        let mut set = HashSet::new();
        set.insert(Self::ZeroTrustAccess);
        set.insert(Self::SecureWebGateway);
        set.insert(Self::CloudAccessSecurityBroker);
        set.insert(Self::DataLossPrevention);
        set.insert(Self::RemoteBrowserIsolation);
        set.insert(Self::AdvancedThreatProtection);
        set.insert(Self::SdWanOptimization);
        set.insert(Self::FirewallAsService);
        set.insert(Self::DnsSecurityFilter);
        set.insert(Self::SslInspection);
        set
    }
}

/// Subscription tier
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionTier {
    Starter,
    Business,
    Enterprise,
    Custom,
}

/// Entitlements for a tenant
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entitlements {
    pub features: HashSet<SaseFeature>,
    pub quotas: ResourceQuotas,
}

/// Resource quotas
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceQuotas {
    pub max_sites: u32,
    pub max_users: u32,
    pub bandwidth_limit_mbps: u32,
    pub policy_limit: u32,
    pub ssl_inspection_gb: u32,
}

impl ResourceQuotas {
    pub fn unlimited() -> Self {
        Self {
            max_sites: u32::MAX,
            max_users: u32::MAX,
            bandwidth_limit_mbps: u32::MAX,
            policy_limit: u32::MAX,
            ssl_inspection_gb: u32::MAX,
        }
    }
}

impl Entitlements {
    pub fn for_tier(tier: SubscriptionTier) -> Self {
        match tier {
            SubscriptionTier::Starter => Self {
                features: {
                    let mut set = HashSet::new();
                    set.insert(SaseFeature::ZeroTrustAccess);
                    set.insert(SaseFeature::SecureWebGateway);
                    set.insert(SaseFeature::DnsSecurityFilter);
                    set
                },
                quotas: ResourceQuotas {
                    max_sites: 5,
                    max_users: 50,
                    bandwidth_limit_mbps: 100,
                    policy_limit: 20,
                    ssl_inspection_gb: 10,
                },
            },
            SubscriptionTier::Business => Self {
                features: {
                    let mut set = HashSet::new();
                    set.insert(SaseFeature::ZeroTrustAccess);
                    set.insert(SaseFeature::SecureWebGateway);
                    set.insert(SaseFeature::CloudAccessSecurityBroker);
                    set.insert(SaseFeature::DataLossPrevention);
                    set.insert(SaseFeature::SdWanOptimization);
                    set.insert(SaseFeature::DnsSecurityFilter);
                    set.insert(SaseFeature::SslInspection);
                    set
                },
                quotas: ResourceQuotas {
                    max_sites: 50,
                    max_users: 500,
                    bandwidth_limit_mbps: 1000,
                    policy_limit: 100,
                    ssl_inspection_gb: 100,
                },
            },
            SubscriptionTier::Enterprise | SubscriptionTier::Custom => Self {
                features: SaseFeature::all(),
                quotas: ResourceQuotas::unlimited(),
            },
        }
    }
    
    pub fn is_entitled_to(&self, feature: &SaseFeature) -> bool {
        self.features.contains(feature)
    }
    
    pub fn check_quota(&self, resource: ResourceType, current: u32) -> Result<(), QuotaError> {
        let limit = match resource {
            ResourceType::Sites => self.quotas.max_sites,
            ResourceType::Users => self.quotas.max_users,
            ResourceType::Policies => self.quotas.policy_limit,
        };
        
        if current >= limit {
            Err(QuotaError::Exceeded { resource, limit, current })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub enum ResourceType { Sites, Users, Policies }

#[derive(Debug, thiserror::Error)]
pub enum QuotaError {
    #[error("Quota exceeded for {resource:?}: limit {limit}, current {current}")]
    Exceeded { resource: ResourceType, limit: u32, current: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum EntitlementError {
    #[error("Feature not entitled: {0:?}")]
    NotEntitled(SaseFeature),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_starter_entitlements() {
        let ent = Entitlements::for_tier(SubscriptionTier::Starter);
        
        assert!(ent.is_entitled_to(&SaseFeature::ZeroTrustAccess));
        assert!(ent.is_entitled_to(&SaseFeature::SecureWebGateway));
        assert!(!ent.is_entitled_to(&SaseFeature::DataLossPrevention));
        assert!(!ent.is_entitled_to(&SaseFeature::RemoteBrowserIsolation));
    }
    
    #[test]
    fn test_enterprise_entitlements() {
        let ent = Entitlements::for_tier(SubscriptionTier::Enterprise);
        
        assert!(ent.is_entitled_to(&SaseFeature::DataLossPrevention));
        assert!(ent.is_entitled_to(&SaseFeature::RemoteBrowserIsolation));
    }
    
    #[test]
    fn test_quota_check() {
        let ent = Entitlements::for_tier(SubscriptionTier::Starter);
        
        assert!(ent.check_quota(ResourceType::Sites, 4).is_ok());
        assert!(ent.check_quota(ResourceType::Sites, 5).is_err());
    }
}
