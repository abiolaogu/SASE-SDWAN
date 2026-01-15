//! Payments domain types
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::Metadata;

/// Payment intent
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentIntent {
    pub id: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub payment_method_id: Option<String>,
    pub capture_method: String,
    #[serde(default)]
    pub charges: Vec<Charge>,
    #[serde(default)]
    pub metadata: Metadata,
    pub created_at: DateTime<Utc>,
}

/// Charge
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Charge {
    pub id: String,
    pub amount: i64,
    pub status: String,
    #[serde(default)]
    pub receipt_url: Option<String>,
}

/// Create payment intent
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreatePaymentIntentParams {
    pub amount: i64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

impl CreatePaymentIntentParams {
    pub fn new(amount: i64, currency: impl Into<String>) -> Self {
        Self { amount, currency: currency.into(), ..Default::default() }
    }
}

/// Subscription
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Subscription {
    pub id: String,
    pub customer_id: String,
    pub plan: SubscriptionPlan,
    pub status: String,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubscriptionPlan {
    pub id: String,
    pub name: String,
    pub amount: i64,
    pub currency: String,
    pub interval: String,
}
