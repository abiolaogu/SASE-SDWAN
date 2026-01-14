//! Billing and Metering

use crate::model::{TenantId, TenantTier};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Billing manager
pub struct BillingManager {
    /// Per-tenant usage
    usage: Arc<RwLock<HashMap<TenantId, UsageMetrics>>>,
    /// Pricing tiers
    pricing: PricingConfig,
}

impl BillingManager {
    pub fn new() -> Self {
        Self {
            usage: Arc::new(RwLock::new(HashMap::new())),
            pricing: PricingConfig::default(),
        }
    }

    /// Record bandwidth usage
    pub fn record_bandwidth(&self, tenant_id: &TenantId, bytes: u64) {
        let mut usage = self.usage.write();
        let metrics = usage.entry(*tenant_id).or_insert_with(UsageMetrics::default);
        metrics.bandwidth_bytes += bytes;
    }

    /// Record API call
    pub fn record_api_call(&self, tenant_id: &TenantId) {
        let mut usage = self.usage.write();
        let metrics = usage.entry(*tenant_id).or_insert_with(UsageMetrics::default);
        metrics.api_calls += 1;
    }

    /// Record active user
    pub fn record_active_user(&self, tenant_id: &TenantId, user_id: &str) {
        let mut usage = self.usage.write();
        let metrics = usage.entry(*tenant_id).or_insert_with(UsageMetrics::default);
        metrics.active_users.insert(user_id.to_string());
    }

    /// Get usage for tenant
    pub fn get_usage(&self, tenant_id: &TenantId) -> Option<UsageMetrics> {
        self.usage.read().get(tenant_id).cloned()
    }

    /// Calculate invoice
    pub fn calculate_invoice(&self, tenant_id: &TenantId, tier: TenantTier) -> Invoice {
        let usage = self.usage.read().get(tenant_id).cloned().unwrap_or_default();
        
        let base_price = self.pricing.base_price(tier);
        let bandwidth_gb = usage.bandwidth_bytes as f64 / 1_000_000_000.0;
        let bandwidth_charge = if bandwidth_gb > 100.0 {
            (bandwidth_gb - 100.0) * 0.05  // $0.05/GB over 100GB
        } else { 0.0 };
        
        let user_count = usage.active_users.len() as u32;
        let user_charge = if user_count > 10 {
            (user_count - 10) as f64 * 5.0  // $5/user over 10
        } else { 0.0 };

        Invoice {
            tenant_id: *tenant_id,
            period_start: usage.period_start,
            period_end: now(),
            base_charge: base_price,
            bandwidth_charge,
            user_charge,
            total: base_price + bandwidth_charge + user_charge,
            currency: "USD".into(),
            line_items: vec![
                LineItem { description: "Base subscription".into(), amount: base_price },
                LineItem { description: format!("Bandwidth ({:.2} GB)", bandwidth_gb), amount: bandwidth_charge },
                LineItem { description: format!("Active users ({})", user_count), amount: user_charge },
            ],
        }
    }

    /// Reset monthly usage
    pub fn reset_period(&self, tenant_id: &TenantId) {
        let mut usage = self.usage.write();
        if let Some(metrics) = usage.get_mut(tenant_id) {
            *metrics = UsageMetrics {
                period_start: now(),
                ..Default::default()
            };
        }
    }
}

impl Default for BillingManager {
    fn default() -> Self { Self::new() }
}

/// Usage metrics per tenant
#[derive(Debug, Clone, Default)]
pub struct UsageMetrics {
    pub period_start: u64,
    pub bandwidth_bytes: u64,
    pub api_calls: u64,
    pub active_users: std::collections::HashSet<String>,
    pub storage_bytes: u64,
    pub features_used: std::collections::HashSet<String>,
}

/// Pricing configuration
#[derive(Debug, Clone)]
pub struct PricingConfig {
    pub free_price: f64,
    pub pro_price: f64,
    pub enterprise_price: f64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            free_price: 0.0,
            pro_price: 99.0,
            enterprise_price: 499.0,
        }
    }
}

impl PricingConfig {
    pub fn base_price(&self, tier: TenantTier) -> f64 {
        match tier {
            TenantTier::Free => self.free_price,
            TenantTier::Pro => self.pro_price,
            TenantTier::Enterprise => self.enterprise_price,
        }
    }
}

/// Invoice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub tenant_id: TenantId,
    pub period_start: u64,
    pub period_end: u64,
    pub base_charge: f64,
    pub bandwidth_charge: f64,
    pub user_charge: f64,
    pub total: f64,
    pub currency: String,
    pub line_items: Vec<LineItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItem {
    pub description: String,
    pub amount: f64,
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
    fn test_billing() {
        let billing = BillingManager::new();
        let tenant = TenantId::new_v4();
        
        billing.record_bandwidth(&tenant, 50_000_000_000);  // 50 GB
        billing.record_active_user(&tenant, "user1");
        billing.record_active_user(&tenant, "user2");
        
        let invoice = billing.calculate_invoice(&tenant, TenantTier::Pro);
        
        assert_eq!(invoice.base_charge, 99.0);
        assert_eq!(invoice.bandwidth_charge, 0.0);  // Under 100GB
        assert_eq!(invoice.user_charge, 0.0);        // Under 10 users
    }
}
