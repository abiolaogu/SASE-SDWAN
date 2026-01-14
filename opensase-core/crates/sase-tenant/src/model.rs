//! Tenant Data Model

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;

/// Tenant ID
pub type TenantId = Uuid;

/// Tenant definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique tenant ID
    pub tenant_id: TenantId,
    /// Display name
    pub name: String,
    /// Subscription tier
    pub tier: TenantTier,
    /// Resource limits
    pub limits: ResourceLimits,
    /// Network configuration
    pub network_config: TenantNetworkConfig,
    /// Security policy
    pub security_policy: TenantSecurityPolicy,
    /// Identity configuration
    pub identity_config: IdentityConfig,
    /// Branding
    pub branding: BrandingConfig,
    /// Metadata
    pub metadata: TenantMetadata,
}

impl Tenant {
    /// Create new tenant
    pub fn new(name: &str, tier: TenantTier) -> Self {
        Self {
            tenant_id: Uuid::new_v4(),
            name: name.to_string(),
            tier,
            limits: ResourceLimits::for_tier(tier),
            network_config: TenantNetworkConfig::default(),
            security_policy: TenantSecurityPolicy::default(),
            identity_config: IdentityConfig::default(),
            branding: BrandingConfig::default(),
            metadata: TenantMetadata::new(),
        }
    }

    /// Check if feature is enabled for this tier
    pub fn has_feature(&self, feature: &str) -> bool {
        self.tier.features().contains(&feature)
    }
}

/// Tenant tier
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TenantTier {
    Free,
    Pro,
    Enterprise,
}

impl TenantTier {
    /// Get features for tier
    pub fn features(&self) -> Vec<&'static str> {
        match self {
            Self::Free => vec!["basic_firewall", "basic_routing"],
            Self::Pro => vec![
                "basic_firewall", "basic_routing",
                "ips", "url_filter", "ssl_inspection",
                "priority_support",
            ],
            Self::Enterprise => vec![
                "basic_firewall", "basic_routing",
                "ips", "url_filter", "ssl_inspection",
                "dlp", "casb", "ztna",
                "custom_branding", "api_access", "sso",
                "dedicated_support", "sla_guarantee",
            ],
        }
    }
}

/// Resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Bandwidth in Mbps
    pub bandwidth_mbps: u64,
    /// Max concurrent connections
    pub max_connections: u64,
    /// Max users
    pub max_users: u32,
    /// Max sites
    pub max_sites: u32,
    /// Log retention days
    pub log_retention_days: u32,
    /// API rate limit (req/min)
    pub api_rate_limit: u32,
    /// Storage quota (GB)
    pub storage_gb: u32,
}

impl ResourceLimits {
    /// Get limits for tier
    pub fn for_tier(tier: TenantTier) -> Self {
        match tier {
            TenantTier::Free => Self {
                bandwidth_mbps: 10,
                max_connections: 100,
                max_users: 5,
                max_sites: 1,
                log_retention_days: 7,
                api_rate_limit: 60,
                storage_gb: 1,
            },
            TenantTier::Pro => Self {
                bandwidth_mbps: 100,
                max_connections: 10_000,
                max_users: 100,
                max_sites: 10,
                log_retention_days: 30,
                api_rate_limit: 1000,
                storage_gb: 100,
            },
            TenantTier::Enterprise => Self {
                bandwidth_mbps: 10_000,
                max_connections: 1_000_000,
                max_users: 10_000,
                max_sites: 1000,
                log_retention_days: 365,
                api_rate_limit: 100_000,
                storage_gb: 10_000,
            },
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantNetworkConfig {
    /// Private overlay network CIDR
    pub overlay_network: String,
    /// Sites
    pub sites: Vec<Site>,
    /// Users
    pub users: Vec<User>,
    /// App connectors
    pub app_connectors: Vec<AppConnector>,
    /// DNS settings
    pub dns_config: DnsConfig,
}

impl Default for TenantNetworkConfig {
    fn default() -> Self {
        Self {
            overlay_network: "10.0.0.0/8".to_string(),
            sites: Vec::new(),
            users: Vec::new(),
            app_connectors: Vec::new(),
            dns_config: DnsConfig::default(),
        }
    }
}

/// Site definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub site_id: Uuid,
    pub name: String,
    pub location: String,
    pub subnet: String,
    pub gateway_ip: String,
}

/// User definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: Uuid,
    pub email: String,
    pub role: TenantRole,
    pub groups: Vec<String>,
    pub device_limit: u32,
}

/// Tenant role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TenantRole {
    SuperAdmin,
    NetworkAdmin,
    SecurityAdmin,
    ReadOnly,
    User,
}

impl TenantRole {
    pub fn permissions(&self) -> Vec<&'static str> {
        match self {
            Self::SuperAdmin => vec!["*"],
            Self::NetworkAdmin => vec!["network:*", "sites:*", "users:read"],
            Self::SecurityAdmin => vec!["security:*", "policies:*", "logs:read"],
            Self::ReadOnly => vec!["*:read"],
            Self::User => vec!["self:*"],
        }
    }
}

/// App connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConnector {
    pub connector_id: Uuid,
    pub name: String,
    pub site_id: Uuid,
    pub apps: Vec<PrivateApp>,
}

/// Private application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateApp {
    pub app_id: Uuid,
    pub name: String,
    pub domain: String,
    pub internal_ip: String,
    pub port: u16,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub primary: String,
    pub secondary: String,
    pub custom_domains: Vec<String>,
    pub split_dns: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            primary: "1.1.1.1".to_string(),
            secondary: "8.8.8.8".to_string(),
            custom_domains: Vec::new(),
            split_dns: false,
        }
    }
}

/// Security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSecurityPolicy {
    pub firewall_rules: Vec<FirewallRule>,
    pub ips_mode: IpsMode,
    pub url_categories_blocked: Vec<String>,
    pub dlp_enabled: bool,
    pub ssl_inspection: SslInspectionConfig,
}

impl Default for TenantSecurityPolicy {
    fn default() -> Self {
        Self {
            firewall_rules: Vec::new(),
            ips_mode: IpsMode::Detect,
            url_categories_blocked: vec!["malware".into(), "phishing".into()],
            dlp_enabled: false,
            ssl_inspection: SslInspectionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub rule_id: Uuid,
    pub name: String,
    pub action: RuleAction,
    pub source: String,
    pub destination: String,
    pub service: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RuleAction { Allow, Deny, Log }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IpsMode { Disabled, Detect, Prevent }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInspectionConfig {
    pub enabled: bool,
    pub bypass_categories: Vec<String>,
}

impl Default for SslInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bypass_categories: vec!["banking".into(), "healthcare".into()],
        }
    }
}

/// Identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub provider: IdentityProvider,
    pub sso_enabled: bool,
    pub mfa_required: bool,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            provider: IdentityProvider::Local,
            sso_enabled: false,
            mfa_required: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityProvider {
    Local,
    Saml { idp_url: String, certificate: String },
    Oidc { issuer: String, client_id: String },
    Ldap { server: String, base_dn: String },
}

/// Branding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingConfig {
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub custom_domain: Option<String>,
    pub email_from: Option<String>,
}

impl Default for BrandingConfig {
    fn default() -> Self {
        Self {
            logo_url: None,
            primary_color: "#0066cc".to_string(),
            custom_domain: None,
            email_from: None,
        }
    }
}

/// Tenant metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMetadata {
    pub created_at: u64,
    pub updated_at: u64,
    pub status: TenantStatus,
    pub tags: HashMap<String, String>,
}

impl TenantMetadata {
    pub fn new() -> Self {
        let now = now();
        Self {
            created_at: now,
            updated_at: now,
            status: TenantStatus::Active,
            tags: HashMap::new(),
        }
    }
}

impl Default for TenantMetadata {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TenantStatus {
    Pending,
    Active,
    Suspended,
    Offboarding,
    Deleted,
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
    fn test_tenant_creation() {
        let tenant = Tenant::new("Acme Corp", TenantTier::Enterprise);
        
        assert_eq!(tenant.name, "Acme Corp");
        assert_eq!(tenant.tier, TenantTier::Enterprise);
        assert!(tenant.has_feature("dlp"));
        assert!(tenant.has_feature("ztna"));
    }

    #[test]
    fn test_tier_limits() {
        let free = ResourceLimits::for_tier(TenantTier::Free);
        let enterprise = ResourceLimits::for_tier(TenantTier::Enterprise);
        
        assert!(enterprise.bandwidth_mbps > free.bandwidth_mbps);
        assert!(enterprise.max_users > free.max_users);
    }
}
