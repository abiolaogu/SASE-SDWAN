//! Subscription Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use uuid::Uuid;
use chrono::{DateTime, Utc, NaiveDate};

/// Subscription manager
pub struct SubscriptionManager {
    subscriptions: Arc<RwLock<HashMap<Uuid, Subscription>>>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create subscription
    pub fn create(&self, tenant_id: Uuid, plan_id: &str, billing_period: BillingPeriod) -> Subscription {
        let now = Utc::now();
        let period_end = match billing_period {
            BillingPeriod::Monthly => now + chrono::Duration::days(30),
            BillingPeriod::Annual => now + chrono::Duration::days(365),
        };

        let subscription = Subscription {
            id: Uuid::new_v4(),
            tenant_id,
            plan_id: plan_id.into(),
            status: SubscriptionStatus::Active,
            billing_period,
            current_period_start: now,
            current_period_end: period_end,
            trial_end: None,
            cancel_at_period_end: false,
            canceled_at: None,
            created_at: now,
        };

        self.subscriptions.write().insert(subscription.id, subscription.clone());
        subscription
    }

    /// Get subscription
    pub fn get(&self, id: Uuid) -> Option<Subscription> {
        self.subscriptions.read().get(&id).cloned()
    }

    /// Get active subscription for tenant
    pub fn get_active(&self, tenant_id: Uuid) -> Option<Subscription> {
        self.subscriptions.read()
            .values()
            .find(|s| s.tenant_id == tenant_id && s.status == SubscriptionStatus::Active)
            .cloned()
    }

    /// Change plan (upgrade/downgrade)
    pub fn change_plan(&self, id: Uuid, new_plan_id: &str, prorate: bool) -> Result<PlanChange, SubscriptionError> {
        let mut subs = self.subscriptions.write();
        let sub = subs.get_mut(&id).ok_or(SubscriptionError::NotFound)?;

        let old_plan = sub.plan_id.clone();
        let proration_amount = if prorate {
            self.calculate_proration(sub, new_plan_id)
        } else {
            dec!(0)
        };

        sub.plan_id = new_plan_id.into();

        Ok(PlanChange {
            subscription_id: id,
            old_plan,
            new_plan: new_plan_id.into(),
            proration_amount,
            effective_at: Utc::now(),
        })
    }

    fn calculate_proration(&self, sub: &Subscription, new_plan: &str) -> Decimal {
        // Simplified proration calculation
        let days_remaining = (sub.current_period_end - Utc::now()).num_days() as f64;
        let total_days = (sub.current_period_end - sub.current_period_start).num_days() as f64;
        let ratio = days_remaining / total_days;

        // In production: look up actual plan prices
        let old_price = dec!(99); // Placeholder
        let new_price = dec!(499); // Placeholder

        let credit = old_price * Decimal::from_f64_retain(ratio).unwrap_or(dec!(0));
        let charge = new_price * Decimal::from_f64_retain(ratio).unwrap_or(dec!(0));

        charge - credit
    }

    /// Cancel subscription
    pub fn cancel(&self, id: Uuid, at_period_end: bool, reason: Option<&str>) -> Result<Subscription, SubscriptionError> {
        let mut subs = self.subscriptions.write();
        let sub = subs.get_mut(&id).ok_or(SubscriptionError::NotFound)?;

        if at_period_end {
            sub.cancel_at_period_end = true;
        } else {
            sub.status = SubscriptionStatus::Canceled;
            sub.canceled_at = Some(Utc::now());
        }

        Ok(sub.clone())
    }

    /// Reactivate canceled subscription
    pub fn reactivate(&self, id: Uuid) -> Result<Subscription, SubscriptionError> {
        let mut subs = self.subscriptions.write();
        let sub = subs.get_mut(&id).ok_or(SubscriptionError::NotFound)?;

        if sub.status != SubscriptionStatus::Canceled && !sub.cancel_at_period_end {
            return Err(SubscriptionError::AlreadyActive);
        }

        sub.status = SubscriptionStatus::Active;
        sub.cancel_at_period_end = false;
        sub.canceled_at = None;

        Ok(sub.clone())
    }

    /// Start trial
    pub fn start_trial(&self, tenant_id: Uuid, plan_id: &str, days: u32) -> Subscription {
        let now = Utc::now();
        let trial_end = now + chrono::Duration::days(days as i64);

        let subscription = Subscription {
            id: Uuid::new_v4(),
            tenant_id,
            plan_id: plan_id.into(),
            status: SubscriptionStatus::Trialing,
            billing_period: BillingPeriod::Monthly,
            current_period_start: now,
            current_period_end: trial_end,
            trial_end: Some(trial_end),
            cancel_at_period_end: false,
            canceled_at: None,
            created_at: now,
        };

        self.subscriptions.write().insert(subscription.id, subscription.clone());
        subscription
    }

    /// Calculate MRR
    pub fn calculate_mrr(&self) -> Decimal {
        // In production: sum of all active subscription amounts normalized to monthly
        let subs = self.subscriptions.read();
        let active_count = subs.values()
            .filter(|s| s.status == SubscriptionStatus::Active)
            .count();

        // Placeholder: assume average of $200/month
        Decimal::from(active_count) * dec!(200)
    }

    /// Get all subscriptions
    pub fn get_all(&self) -> Vec<Subscription> {
        self.subscriptions.read().values().cloned().collect()
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self { Self::new() }
}

/// Subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub plan_id: String,
    pub status: SubscriptionStatus,
    pub billing_period: BillingPeriod,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub trial_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionStatus {
    Active,
    Trialing,
    PastDue,
    Canceled,
    Unpaid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BillingPeriod {
    Monthly,
    Annual,
}

/// Plan change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanChange {
    pub subscription_id: Uuid,
    pub old_plan: String,
    pub new_plan: String,
    pub proration_amount: Decimal,
    pub effective_at: DateTime<Utc>,
}

/// Subscription error
#[derive(Debug, Clone)]
pub enum SubscriptionError {
    NotFound,
    AlreadyActive,
    AlreadyCanceled,
    InvalidPlan,
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Subscription not found"),
            Self::AlreadyActive => write!(f, "Subscription already active"),
            Self::AlreadyCanceled => write!(f, "Subscription already canceled"),
            Self::InvalidPlan => write!(f, "Invalid plan"),
        }
    }
}
