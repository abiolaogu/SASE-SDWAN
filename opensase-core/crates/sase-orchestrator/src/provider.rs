//! Cloud Provider Definitions

use serde::{Deserialize, Serialize};

/// Supported cloud providers
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    // Tier 1 - Full featured
    Aws,
    Gcp,
    Azure,
    
    // Tier 2 - Cost-optimized
    Vultr,
    DigitalOcean,
    Linode,
    Hetzner,
    
    // Tier 3 - Bare metal / Performance
    EquinixMetal,
    Packet,
    OvhCloud,
}

impl CloudProvider {
    /// Get tier
    pub fn tier(&self) -> ProviderTier {
        match self {
            Self::Aws | Self::Gcp | Self::Azure => ProviderTier::Tier1,
            Self::Vultr | Self::DigitalOcean | Self::Linode | Self::Hetzner => ProviderTier::Tier2,
            Self::EquinixMetal | Self::Packet | Self::OvhCloud => ProviderTier::Tier3,
        }
    }

    /// Get Terraform provider name
    pub fn terraform_provider(&self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "google",
            Self::Azure => "azurerm",
            Self::Vultr => "vultr",
            Self::DigitalOcean => "digitalocean",
            Self::Linode => "linode",
            Self::Hetzner => "hcloud",
            Self::EquinixMetal => "equinix",
            Self::Packet => "packet",
            Self::OvhCloud => "ovh",
        }
    }

    /// Get available regions
    pub fn regions(&self) -> Vec<&'static str> {
        match self {
            Self::Aws => vec![
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-central-1",
                "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            ],
            Self::Gcp => vec![
                "us-central1", "us-east1", "us-west1",
                "europe-west1", "europe-west2",
                "asia-east1", "asia-southeast1",
            ],
            Self::Azure => vec![
                "eastus", "eastus2", "westus", "westus2",
                "northeurope", "westeurope",
                "southeastasia", "eastasia",
            ],
            Self::Vultr => vec![
                "ewr", "ord", "dfw", "lax", "atl",
                "ams", "lhr", "fra", "cdg",
                "nrt", "sgp", "syd",
            ],
            Self::DigitalOcean => vec![
                "nyc1", "nyc3", "sfo1", "sfo3",
                "ams3", "lon1", "fra1",
                "sgp1", "blr1", "syd1",
            ],
            _ => vec!["default"],
        }
    }

    /// Check if supports anycast
    pub fn supports_anycast(&self) -> bool {
        matches!(self, Self::Aws | Self::Gcp | Self::EquinixMetal)
    }

    /// Check if supports BGP
    pub fn supports_bgp(&self) -> bool {
        matches!(self, Self::Aws | Self::Gcp | Self::EquinixMetal | Self::Vultr)
    }

    /// Get default instance type for capacity
    pub fn instance_type(&self, vcpus: u32, memory_gb: u32) -> String {
        match self {
            Self::Aws => {
                if vcpus <= 2 { "t3.small".into() }
                else if vcpus <= 4 { "c5.xlarge".into() }
                else if vcpus <= 8 { "c5.2xlarge".into() }
                else { "c5.4xlarge".into() }
            }
            Self::Gcp => {
                if vcpus <= 2 { "e2-small".into() }
                else if vcpus <= 4 { "n2-standard-4".into() }
                else { "n2-standard-8".into() }
            }
            Self::Azure => {
                if vcpus <= 2 { "Standard_B2s".into() }
                else if vcpus <= 4 { "Standard_D4s_v3".into() }
                else { "Standard_D8s_v3".into() }
            }
            Self::Vultr => {
                if vcpus <= 2 { "vc2-2c-4gb".into() }
                else if vcpus <= 4 { "vc2-4c-8gb".into() }
                else { "vc2-8c-32gb".into() }
            }
            Self::DigitalOcean => {
                if vcpus <= 2 { "s-2vcpu-4gb".into() }
                else if vcpus <= 4 { "s-4vcpu-8gb".into() }
                else { "s-8vcpu-16gb".into() }
            }
            _ => format!("{}vcpu-{}gb", vcpus, memory_gb),
        }
    }
}

/// Provider tier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTier {
    /// Full featured (AWS, GCP, Azure)
    Tier1,
    /// Cost-optimized (Vultr, DO, Linode)
    Tier2,
    /// Bare metal / Performance
    Tier3,
}

/// Provider credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCredentials {
    pub provider: CloudProvider,
    pub credentials: CredentialType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    ApiKey { key: String },
    AccessKey { access_key: String, secret_key: String },
    ServiceAccount { json_key: String },
    OAuth { token: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_tiers() {
        assert_eq!(CloudProvider::Aws.tier(), ProviderTier::Tier1);
        assert_eq!(CloudProvider::Vultr.tier(), ProviderTier::Tier2);
        assert_eq!(CloudProvider::EquinixMetal.tier(), ProviderTier::Tier3);
    }

    #[test]
    fn test_instance_types() {
        let aws_small = CloudProvider::Aws.instance_type(2, 4);
        assert_eq!(aws_small, "t3.small");
        
        let aws_large = CloudProvider::Aws.instance_type(16, 32);
        assert_eq!(aws_large, "c5.4xlarge");
    }
}
