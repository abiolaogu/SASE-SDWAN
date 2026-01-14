//! Dedicated Server Provider Definitions
//!
//! OpenSASE uses dedicated physical servers only - no hyperscaler VMs.
//! Supported providers: Voxility, OVH Cloud, Hetzner, Scaleway, etc.

use serde::{Deserialize, Serialize};

/// Supported dedicated server providers (no hyperscaler VMs)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DedicatedProvider {
    // Tier 1 - Premium Dedicated Servers
    Voxility,
    EquinixMetal,
    
    // Tier 2 - Cost-Effective Dedicated Servers  
    OvhCloud,
    Hetzner,
    Scaleway,
    
    // Tier 3 - Budget Dedicated Servers
    Leaseweb,
    ServerHub,
    ReliableSite,
    PhoenixNap,
}

// Backwards compatibility alias
pub type CloudProvider = DedicatedProvider;

impl DedicatedProvider {
    /// Get tier
    pub fn tier(&self) -> ProviderTier {
        match self {
            Self::Voxility | Self::EquinixMetal => ProviderTier::Tier1,
            Self::OvhCloud | Self::Hetzner | Self::Scaleway => ProviderTier::Tier2,
            Self::Leaseweb | Self::ServerHub | Self::ReliableSite | Self::PhoenixNap => ProviderTier::Tier3,
        }
    }

    /// Get Terraform provider name
    pub fn terraform_provider(&self) -> &'static str {
        match self {
            Self::OvhCloud => "ovh",
            Self::Hetzner => "hcloud",
            Self::Scaleway => "scaleway",
            Self::EquinixMetal => "equinix",
            Self::Voxility => "null",  // Custom provisioning via API
            Self::Leaseweb => "null",
            Self::ServerHub => "null",
            Self::ReliableSite => "null",
            Self::PhoenixNap => "pnap",
        }
    }

    /// Get available datacenter locations
    pub fn regions(&self) -> Vec<&'static str> {
        match self {
            Self::Voxility => vec![
                "ams", "lon", "fra", "par", "buc", "sof", "waw",  // Europe
                "nyc", "lax", "chi", "dal", "mia",                 // North America
                "sgp", "hkg", "tyo",                               // Asia Pacific
            ],
            Self::OvhCloud => vec![
                "gra", "sbg", "rbx", "bhs", "waw",                 // Europe
                "sgp", "syd",                                       // Asia Pacific
                "us-east-va", "us-west-or",                        // North America
            ],
            Self::Hetzner => vec![
                "fsn1", "nbg1", "hel1",                            // Europe (Falkenstein, Nuremberg, Helsinki)
                "ash",                                              // North America (Ashburn)
                "hil",                                              // North America (Hillsboro)
            ],
            Self::Scaleway => vec![
                "fr-par", "nl-ams", "pl-waw",                      // Europe
            ],
            Self::EquinixMetal => vec![
                "am", "dc", "ny", "sv", "la", "da", "ch", "at",    // North America
                "ld", "fr", "pa", "am",                            // Europe
                "sg", "ty", "sy",                                   // Asia Pacific
            ],
            Self::Leaseweb => vec![
                "ams", "fra", "lon", "sin", "hkg", "syd",
                "wdc", "sfo", "dal",
            ],
            Self::PhoenixNap => vec![
                "phx", "ash", "sgp", "ams",
            ],
            _ => vec!["default"],
        }
    }

    /// All providers support BGP on dedicated servers
    pub fn supports_bgp(&self) -> bool {
        match self {
            Self::Voxility | Self::EquinixMetal | Self::OvhCloud | Self::PhoenixNap => true,
            Self::Hetzner | Self::Scaleway => true,  // Available on dedicated
            _ => false,
        }
    }

    /// Check if supports anycast
    pub fn supports_anycast(&self) -> bool {
        matches!(self, Self::Voxility | Self::EquinixMetal | Self::OvhCloud)
    }

    /// Get recommended server configuration for capacity needs
    pub fn server_config(&self, vcpus: u32, memory_gb: u32) -> ServerConfig {
        match self {
            Self::Hetzner => {
                if vcpus <= 8 { ServerConfig::new("AX41-NVMe", 6, 64, 512) }
                else if vcpus <= 16 { ServerConfig::new("AX101", 12, 128, 2048) }
                else { ServerConfig::new("AX161", 32, 256, 4096) }
            }
            Self::OvhCloud => {
                if vcpus <= 8 { ServerConfig::new("Advance-1", 8, 64, 500) }
                else if vcpus <= 16 { ServerConfig::new("Advance-2", 16, 128, 1000) }
                else { ServerConfig::new("Scale-1", 32, 256, 2000) }
            }
            Self::Scaleway => {
                if vcpus <= 8 { ServerConfig::new("CORE-8-S", 8, 32, 500) }
                else if vcpus <= 16 { ServerConfig::new("CORE-16-M", 16, 64, 1000) }
                else { ServerConfig::new("CORE-32-L", 32, 128, 2000) }
            }
            Self::Voxility => {
                if vcpus <= 8 { ServerConfig::new("Dedicated-S", 8, 64, 1000) }
                else if vcpus <= 16 { ServerConfig::new("Dedicated-M", 16, 128, 2000) }
                else { ServerConfig::new("Dedicated-L", 32, 256, 4000) }
            }
            Self::EquinixMetal => {
                if vcpus <= 8 { ServerConfig::new("m3.small.x86", 8, 64, 480) }
                else if vcpus <= 16 { ServerConfig::new("m3.large.x86", 16, 256, 960) }
                else { ServerConfig::new("n3.xlarge.x86", 32, 512, 3840) }
            }
            _ => ServerConfig::new(&format!("{}-vcpu-{}gb", vcpus, memory_gb), vcpus, memory_gb, 500),
        }
    }

    /// Get instance type string (for backwards compatibility)
    pub fn instance_type(&self, vcpus: u32, memory_gb: u32) -> String {
        self.server_config(vcpus, memory_gb).model.clone()
    }

    /// Get monthly base cost estimate (USD)
    pub fn monthly_cost(&self, config: &ServerConfig) -> f64 {
        match self {
            Self::Hetzner => {
                // Hetzner is known for excellent value
                match config.model.as_str() {
                    "AX41-NVMe" => 50.0,
                    "AX101" => 130.0,
                    "AX161" => 200.0,
                    _ => 100.0,
                }
            }
            Self::OvhCloud => {
                match config.model.as_str() {
                    "Advance-1" => 80.0,
                    "Advance-2" => 160.0,
                    "Scale-1" => 280.0,
                    _ => 120.0,
                }
            }
            Self::Scaleway => {
                match config.model.as_str() {
                    "CORE-8-S" => 70.0,
                    "CORE-16-M" => 140.0,
                    "CORE-32-L" => 250.0,
                    _ => 100.0,
                }
            }
            Self::Voxility => {
                // Premium DDoS-protected hosting
                (config.vcpus as f64) * 15.0 + (config.memory_gb as f64) * 2.0
            }
            Self::EquinixMetal => {
                // Premium bare metal
                match config.model.as_str() {
                    "m3.small.x86" => 500.0,
                    "m3.large.x86" => 1100.0,
                    "n3.xlarge.x86" => 2500.0,
                    _ => 800.0,
                }
            }
            _ => 150.0,
        }
    }

    /// Get egress cost per GB (most dedicated providers include generous transfer)
    pub fn egress_cost_per_gb(&self) -> f64 {
        match self {
            Self::Hetzner => 0.0,       // 20TB+ included
            Self::OvhCloud => 0.0,       // Unlimited included on most plans
            Self::Scaleway => 0.0,       // 1TB+ included
            Self::Voxility => 0.002,     // Very cheap egress
            Self::EquinixMetal => 0.05,  // Premium pricing
            Self::Leaseweb => 0.0,       // Included
            _ => 0.01,
        }
    }
}

/// Server configuration for dedicated servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub model: String,
    pub vcpus: u32,
    pub memory_gb: u32,
    pub storage_gb: u32,
}

impl ServerConfig {
    pub fn new(model: &str, vcpus: u32, memory_gb: u32, storage_gb: u32) -> Self {
        Self {
            model: model.to_string(),
            vcpus,
            memory_gb,
            storage_gb,
        }
    }
}

/// Provider tier (based on features, not on being cloud/dedicated)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTier {
    /// Premium dedicated (Voxility, Equinix Metal)
    Tier1,
    /// Cost-effective dedicated (OVH, Hetzner, Scaleway)
    Tier2,
    /// Budget dedicated
    Tier3,
}

/// Provider credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCredentials {
    pub provider: DedicatedProvider,
    pub credentials: CredentialType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    ApiKey { key: String },
    AccessKey { access_key: String, secret_key: String },
    SshKey { private_key: String, public_key: String },
    OAuth { token: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_tiers() {
        assert_eq!(DedicatedProvider::Voxility.tier(), ProviderTier::Tier1);
        assert_eq!(DedicatedProvider::Hetzner.tier(), ProviderTier::Tier2);
        assert_eq!(DedicatedProvider::Leaseweb.tier(), ProviderTier::Tier3);
    }

    #[test]
    fn test_server_configs() {
        let hetzner_small = DedicatedProvider::Hetzner.server_config(4, 32);
        assert_eq!(hetzner_small.model, "AX41-NVMe");
        
        let ovh_large = DedicatedProvider::OvhCloud.server_config(32, 128);
        assert_eq!(ovh_large.model, "Scale-1");
    }

    #[test]
    fn test_egress_costs() {
        // Dedicated servers typically have free or very cheap egress
        assert_eq!(DedicatedProvider::Hetzner.egress_cost_per_gb(), 0.0);
        assert_eq!(DedicatedProvider::OvhCloud.egress_cost_per_gb(), 0.0);
        assert!(DedicatedProvider::Voxility.egress_cost_per_gb() < 0.01);
    }

    #[test]
    fn test_bgp_support() {
        // All Tier 1/2 providers support BGP on dedicated
        assert!(DedicatedProvider::Voxility.supports_bgp());
        assert!(DedicatedProvider::OvhCloud.supports_bgp());
        assert!(DedicatedProvider::Hetzner.supports_bgp());
    }
}
