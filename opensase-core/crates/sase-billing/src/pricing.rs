//! Pricing Engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use uuid::Uuid;

use crate::metering::MonthlyUsage;

/// Pricing engine
pub struct PricingEngine {
    /// Available plans
    plans: Arc<RwLock<HashMap<String, Plan>>>,
    /// Custom pricing overrides
    custom: Arc<RwLock<HashMap<Uuid, CustomPricing>>>,
}

impl PricingEngine {
    pub fn new() -> Self {
        let engine = Self {
            plans: Arc::new(RwLock::new(HashMap::new())),
            custom: Arc::new(RwLock::new(HashMap::new())),
        };
        engine.load_default_plans();
        engine
    }

    fn load_default_plans(&self) {
        let mut plans = self.plans.write();
        
        // Free tier
        plans.insert("free".into(), Plan {
            id: "free".into(),
            name: "Free".into(),
            tier: PricingTier::Free,
            base_price: dec!(0),
            billing_period: BillingPeriod::Monthly,
            included: UsageLimits {
                bandwidth_gb: 10,
                users: 5,
                devices: 10,
                apps: 3,
                api_requests: 10_000,
            },
            overage_rates: OverageRates::default(),
            features: vec!["basic_security".into()],
        });

        // Pro tier
        plans.insert("pro".into(), Plan {
            id: "pro".into(),
            name: "Pro".into(),
            tier: PricingTier::Pro,
            base_price: dec!(99),
            billing_period: BillingPeriod::Monthly,
            included: UsageLimits {
                bandwidth_gb: 100,
                users: 50,
                devices: 100,
                apps: 20,
                api_requests: 100_000,
            },
            overage_rates: OverageRates {
                per_gb: dec!(0.10),
                per_user: dec!(5),
                per_device: dec!(2),
                per_app: dec!(10),
                per_1k_api_requests: dec!(0.50),
            },
            features: vec!["basic_security".into(), "ztna".into(), "casb".into()],
        });

        // Enterprise tier
        plans.insert("enterprise".into(), Plan {
            id: "enterprise".into(),
            name: "Enterprise".into(),
            tier: PricingTier::Enterprise,
            base_price: dec!(499),
            billing_period: BillingPeriod::Monthly,
            included: UsageLimits {
                bandwidth_gb: 1000,
                users: 500,
                devices: 1000,
                apps: 100,
                api_requests: 1_000_000,
            },
            overage_rates: OverageRates {
                per_gb: dec!(0.05),
                per_user: dec!(3),
                per_device: dec!(1),
                per_app: dec!(5),
                per_1k_api_requests: dec!(0.25),
            },
            features: vec!["basic_security".into(), "ztna".into(), "casb".into(), "dlp".into(), "siem".into()],
        });
    }

    /// Get plan
    pub fn get_plan(&self, plan_id: &str) -> Option<Plan> {
        self.plans.read().get(plan_id).cloned()
    }

    /// Get all plans
    pub fn get_plans(&self) -> Vec<Plan> {
        self.plans.read().values().cloned().collect()
    }

    /// Calculate invoice amount
    pub fn calculate(&self, tenant_id: Uuid, plan_id: &str, usage: &MonthlyUsage) -> PricingResult {
        let plan = match self.get_plan(plan_id) {
            Some(p) => p,
            None => return PricingResult::error("Plan not found"),
        };

        // Check for custom pricing
        let custom = self.custom.read().get(&tenant_id).cloned();

        let base_price = custom.as_ref()
            .and_then(|c| c.custom_base_price)
            .unwrap_or(plan.base_price);

        let rates = custom.as_ref()
            .map(|c| c.overage_rates.clone())
            .unwrap_or(plan.overage_rates.clone());

        // Calculate overages
        let mut line_items = Vec::new();
        let mut total_overages = dec!(0);

        // Bandwidth overage
        let bandwidth_used = (usage.total_bandwidth_ingress_gb + usage.total_bandwidth_egress_gb) as u64;
        if bandwidth_used > plan.included.bandwidth_gb {
            let overage = bandwidth_used - plan.included.bandwidth_gb;
            let charge = rates.per_gb * Decimal::from(overage);
            line_items.push(LineItem {
                description: format!("Bandwidth overage ({} GB)", overage),
                quantity: overage as f64,
                unit_price: rates.per_gb,
                amount: charge,
            });
            total_overages += charge;
        }

        // User overage
        if usage.peak_users > plan.included.users {
            let overage = usage.peak_users - plan.included.users;
            let charge = rates.per_user * Decimal::from(overage);
            line_items.push(LineItem {
                description: format!("Additional users ({} users)", overage),
                quantity: overage as f64,
                unit_price: rates.per_user,
                amount: charge,
            });
            total_overages += charge;
        }

        // API request overage
        let api_1k = usage.total_api_requests / 1000;
        let included_1k = plan.included.api_requests / 1000;
        if api_1k > included_1k {
            let overage = api_1k - included_1k;
            let charge = rates.per_1k_api_requests * Decimal::from(overage);
            line_items.push(LineItem {
                description: format!("API requests overage ({} thousand)", overage),
                quantity: overage as f64,
                unit_price: rates.per_1k_api_requests,
                amount: charge,
            });
            total_overages += charge;
        }

        // Apply committed use discount if applicable
        let discount = custom.as_ref()
            .and_then(|c| c.committed_discount_percent)
            .map(|d| (base_price + total_overages) * d / dec!(100))
            .unwrap_or(dec!(0));

        let subtotal = base_price + total_overages - discount;

        PricingResult {
            success: true,
            base_price,
            line_items,
            subtotal,
            discount,
            total: subtotal,
            error: None,
        }
    }

    /// Set custom pricing for tenant
    pub fn set_custom_pricing(&self, tenant_id: Uuid, custom: CustomPricing) {
        self.custom.write().insert(tenant_id, custom);
    }
}

impl Default for PricingEngine {
    fn default() -> Self { Self::new() }
}

/// Subscription plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub tier: PricingTier,
    pub base_price: Decimal,
    pub billing_period: BillingPeriod,
    pub included: UsageLimits,
    pub overage_rates: OverageRates,
    pub features: Vec<String>,
}

/// Pricing tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PricingTier {
    Free,
    Pro,
    Enterprise,
    Custom,
}

/// Billing period
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BillingPeriod {
    Monthly,
    Annual,
}

/// Usage limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLimits {
    pub bandwidth_gb: u64,
    pub users: u64,
    pub devices: u64,
    pub apps: u64,
    pub api_requests: u64,
}

/// Overage rates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverageRates {
    pub per_gb: Decimal,
    pub per_user: Decimal,
    pub per_device: Decimal,
    pub per_app: Decimal,
    pub per_1k_api_requests: Decimal,
}

impl Default for OverageRates {
    fn default() -> Self {
        Self {
            per_gb: dec!(0),
            per_user: dec!(0),
            per_device: dec!(0),
            per_app: dec!(0),
            per_1k_api_requests: dec!(0),
        }
    }
}

/// Custom pricing overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPricing {
    pub tenant_id: Uuid,
    pub custom_base_price: Option<Decimal>,
    pub overage_rates: OverageRates,
    pub committed_discount_percent: Option<Decimal>,
    pub contract_end: Option<chrono::NaiveDate>,
}

/// Invoice line item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItem {
    pub description: String,
    pub quantity: f64,
    pub unit_price: Decimal,
    pub amount: Decimal,
}

/// Pricing calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingResult {
    pub success: bool,
    pub base_price: Decimal,
    pub line_items: Vec<LineItem>,
    pub subtotal: Decimal,
    pub discount: Decimal,
    pub total: Decimal,
    pub error: Option<String>,
}

impl PricingResult {
    fn error(msg: &str) -> Self {
        Self {
            success: false,
            base_price: dec!(0),
            line_items: vec![],
            subtotal: dec!(0),
            discount: dec!(0),
            total: dec!(0),
            error: Some(msg.into()),
        }
    }
}
