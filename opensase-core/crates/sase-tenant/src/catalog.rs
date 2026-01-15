//! Service Catalog for Self-Service Portal
//!
//! Adapted from eCommerce catalog patterns for SASE service offerings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Service category
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceCategory {
    ZeroTrust,
    SecureWeb,
    CloudSecurity,
    NetworkOptimization,
    ThreatProtection,
    Compliance,
}

/// SASE service offering
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SaseServiceOffering {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ServiceCategory,
    pub features: Vec<String>,
    pub pricing: PricingModel,
    pub prerequisites: Vec<String>,
    pub included_in_tiers: Vec<String>,
}

/// Pricing model
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PricingModel {
    pub pricing_type: PricingType,
    pub base_price_cents: u64,
    pub currency: String,
    pub tiers: Vec<PricingTier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PricingType { PerUser, PerSite, Bandwidth, Flat }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PricingTier {
    pub min_quantity: u32,
    pub max_quantity: Option<u32>,
    pub price_cents: u64,
}

/// Service catalog
pub struct ServiceCatalog {
    offerings: HashMap<String, SaseServiceOffering>,
}

impl ServiceCatalog {
    pub fn new() -> Self {
        let mut offerings = HashMap::new();
        
        offerings.insert("ztna".into(), SaseServiceOffering {
            id: "ztna".into(),
            name: "Zero Trust Network Access".into(),
            description: "Secure remote access with identity-based policies".into(),
            category: ServiceCategory::ZeroTrust,
            features: vec!["Identity verification".into(), "Device posture".into(), "App-level access".into()],
            pricing: PricingModel {
                pricing_type: PricingType::PerUser,
                base_price_cents: 500,
                currency: "USD".into(),
                tiers: vec![],
            },
            prerequisites: vec![],
            included_in_tiers: vec!["starter".into(), "business".into(), "enterprise".into()],
        });
        
        offerings.insert("swg".into(), SaseServiceOffering {
            id: "swg".into(),
            name: "Secure Web Gateway".into(),
            description: "Web filtering and threat protection".into(),
            category: ServiceCategory::SecureWeb,
            features: vec!["URL filtering".into(), "Malware protection".into(), "SSL inspection".into()],
            pricing: PricingModel {
                pricing_type: PricingType::PerUser,
                base_price_cents: 300,
                currency: "USD".into(),
                tiers: vec![],
            },
            prerequisites: vec![],
            included_in_tiers: vec!["starter".into(), "business".into(), "enterprise".into()],
        });
        
        offerings.insert("dlp".into(), SaseServiceOffering {
            id: "dlp".into(),
            name: "Data Loss Prevention".into(),
            description: "Protect sensitive data across all channels".into(),
            category: ServiceCategory::Compliance,
            features: vec!["Content inspection".into(), "Policy enforcement".into(), "Incident management".into()],
            pricing: PricingModel {
                pricing_type: PricingType::PerUser,
                base_price_cents: 800,
                currency: "USD".into(),
                tiers: vec![],
            },
            prerequisites: vec!["swg".into()],
            included_in_tiers: vec!["business".into(), "enterprise".into()],
        });
        
        Self { offerings }
    }
    
    pub fn get(&self, id: &str) -> Option<&SaseServiceOffering> {
        self.offerings.get(id)
    }
    
    pub fn list_by_category(&self, category: ServiceCategory) -> Vec<&SaseServiceOffering> {
        self.offerings.values()
            .filter(|o| o.category == category)
            .collect()
    }
    
    pub fn list_for_tier(&self, tier: &str) -> Vec<&SaseServiceOffering> {
        self.offerings.values()
            .filter(|o| o.included_in_tiers.contains(&tier.to_string()))
            .collect()
    }
}

impl Default for ServiceCatalog {
    fn default() -> Self { Self::new() }
}

/// Service cart for configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceCart {
    pub tenant_id: String,
    pub items: Vec<ServiceCartItem>,
    pub estimated_monthly_cents: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceCartItem {
    pub service_id: String,
    pub quantity: u32,
    pub options: HashMap<String, String>,
}

impl ServiceCart {
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            items: vec![],
            estimated_monthly_cents: 0,
        }
    }
    
    pub fn add_item(&mut self, catalog: &ServiceCatalog, service_id: &str, quantity: u32) -> Result<(), CartError> {
        let offering = catalog.get(service_id).ok_or(CartError::ServiceNotFound)?;
        
        self.items.push(ServiceCartItem {
            service_id: service_id.into(),
            quantity,
            options: HashMap::new(),
        });
        
        self.estimated_monthly_cents += offering.pricing.base_price_cents * quantity as u64;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CartError {
    #[error("Service not found")]
    ServiceNotFound,
    #[error("Prerequisite not met")]
    PrerequisiteNotMet,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_catalog() {
        let catalog = ServiceCatalog::new();
        
        assert!(catalog.get("ztna").is_some());
        assert!(catalog.get("swg").is_some());
        assert!(catalog.get("dlp").is_some());
    }
    
    #[test]
    fn test_list_by_tier() {
        let catalog = ServiceCatalog::new();
        let starter_services = catalog.list_for_tier("starter");
        
        assert!(starter_services.len() >= 2);
    }
    
    #[test]
    fn test_cart() {
        let catalog = ServiceCatalog::new();
        let mut cart = ServiceCart::new("tenant_001");
        
        cart.add_item(&catalog, "ztna", 50).unwrap();
        
        assert_eq!(cart.items.len(), 1);
        assert!(cart.estimated_monthly_cents > 0);
    }
}
