//! OpenSASE Revenue Platform (OSRP)
//!
//! Complete billing and metering system for usage-based pricing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     REVENUE PLATFORM (OSRP)                             │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    METERING ENGINE                               │   │
//! │  │   Usage Events ─► Aggregation ─► Hourly/Daily/Monthly             │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │   Pricing    │  │   Invoice    │  │   Payment    │  │ Subscription│ │
//! │  │   Engine     │  │  Generation  │  │  (Stripe)    │  │ Management  │ │
//! │  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                 CREDITS & PROMOTIONS                             │   │
//! │  │   Sign-up | Referral | Compensation | Promo Codes                │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod metering;
pub mod pricing;
pub mod invoicing;
pub mod payments;
pub mod subscriptions;
pub mod credits;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;
use rust_decimal::Decimal;
use uuid::Uuid;

pub use metering::{MeteringEngine, UsageEvent, UsageMetric};
pub use pricing::{PricingEngine, Plan, PricingTier};
pub use invoicing::{InvoiceGenerator, Invoice};
pub use payments::{PaymentProcessor, PaymentMethod};
pub use subscriptions::{SubscriptionManager, Subscription};
pub use credits::{CreditManager, Credit};

/// Billing error types
#[derive(Debug, Error)]
pub enum BillingError {
    #[error("metering error: {0}")]
    Metering(String),
    #[error("pricing error: {0}")]
    Pricing(String),
    #[error("payment error: {0}")]
    Payment(String),
    #[error("invoice error: {0}")]
    Invoice(String),
}

/// Revenue Platform
pub struct RevenuePlatform {
    /// Metering engine
    pub metering: Arc<MeteringEngine>,
    /// Pricing engine
    pub pricing: Arc<PricingEngine>,
    /// Invoice generator
    pub invoicing: Arc<InvoiceGenerator>,
    /// Payment processor
    pub payments: Arc<PaymentProcessor>,
    /// Subscription manager
    pub subscriptions: Arc<SubscriptionManager>,
    /// Credit manager
    pub credits: Arc<CreditManager>,
}

impl RevenuePlatform {
    /// Create new revenue platform
    pub fn new() -> Self {
        let pricing = Arc::new(PricingEngine::new());
        Self {
            metering: Arc::new(MeteringEngine::new()),
            pricing: pricing.clone(),
            invoicing: Arc::new(InvoiceGenerator::new(pricing.clone())),
            payments: Arc::new(PaymentProcessor::new()),
            subscriptions: Arc::new(SubscriptionManager::new()),
            credits: Arc::new(CreditManager::new()),
        }
    }

    /// Record usage event
    pub fn record_usage(&self, event: UsageEvent) {
        self.metering.record(event);
    }

    /// Generate monthly invoice for tenant
    pub fn generate_invoice(&self, tenant_id: Uuid, month: chrono::NaiveDate) -> Result<Invoice, BillingError> {
        let usage = self.metering.get_monthly_usage(tenant_id, month);
        let subscription = self.subscriptions.get_active(tenant_id)
            .ok_or_else(|| BillingError::Invoice("No active subscription".into()))?;
        let credits = self.credits.get_available(tenant_id);
        
        self.invoicing.generate(tenant_id, &subscription, &usage, &credits)
    }

    /// Get MRR (Monthly Recurring Revenue)
    pub fn get_mrr(&self) -> Decimal {
        self.subscriptions.calculate_mrr()
    }

    /// Get ARR (Annual Recurring Revenue)
    pub fn get_arr(&self) -> Decimal {
        self.get_mrr() * Decimal::from(12)
    }
}

impl Default for RevenuePlatform {
    fn default() -> Self { Self::new() }
}
