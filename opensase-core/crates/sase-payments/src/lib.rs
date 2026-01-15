//! OpenSASE Payment Gateway
//!
//! Payment gateway abstraction layer supporting multiple providers.
//!
//! ## Features
//! - Multi-provider support (Stripe, PayPal, etc.)
//! - PCI-compliant tokenization
//! - Recurring billing
//! - Refunds and disputes

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    pub id: String,
    pub provider: PaymentProvider,
    pub provider_payment_id: Option<String>,
    pub amount: Money,
    pub status: PaymentStatus,
    pub customer_id: Option<String>,
    pub payment_method_id: Option<String>,
    pub description: Option<String>,
    pub metadata: HashMap<String, String>,
    pub failure_reason: Option<String>,
    pub refunded_amount: Money,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Money {
    pub amount: Decimal,
    pub currency: String,
}

impl Money {
    pub fn zero(currency: &str) -> Self {
        Self {
            amount: Decimal::ZERO,
            currency: currency.to_string(),
        }
    }
    
    pub fn new(amount: Decimal, currency: &str) -> Self {
        Self {
            amount,
            currency: currency.to_string(),
        }
    }
}

impl Default for Money {
    fn default() -> Self {
        Self::zero("USD")
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentStatus {
    #[default]
    Pending,
    Processing,
    RequiresAction,
    Succeeded,
    Failed,
    Cancelled,
    Refunded,
    PartiallyRefunded,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum PaymentProvider {
    #[default]
    Internal,
    Stripe,
    PayPal,
    Square,
    Adyen,
    Braintree,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentMethod {
    pub id: String,
    pub customer_id: String,
    pub method_type: PaymentMethodType,
    pub is_default: bool,
    pub billing_details: BillingDetails,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaymentMethodType {
    Card(CardDetails),
    BankAccount(BankAccountDetails),
    Wallet(WalletType),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CardDetails {
    pub brand: String,
    pub last4: String,
    pub exp_month: u8,
    pub exp_year: u16,
    pub fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BankAccountDetails {
    pub bank_name: String,
    pub last4: String,
    pub account_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WalletType {
    ApplePay,
    GooglePay,
    PayPal,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BillingDetails {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Address {
    pub line1: Option<String>,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub customer_id: String,
    pub plan_id: String,
    pub status: SubscriptionStatus,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub cancelled_at: Option<DateTime<Utc>>,
    pub payment_method_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum SubscriptionStatus {
    #[default]
    Active,
    Trialing,
    PastDue,
    Cancelled,
    Unpaid,
    Paused,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Refund {
    pub id: String,
    pub payment_id: String,
    pub amount: Money,
    pub reason: Option<String>,
    pub status: RefundStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum RefundStatus {
    #[default]
    Pending,
    Succeeded,
    Failed,
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum PaymentError {
    #[error("Payment not found")]
    PaymentNotFound,
    
    #[error("Payment method not found")]
    PaymentMethodNotFound,
    
    #[error("Payment failed: {0}")]
    PaymentFailed(String),
    
    #[error("Card declined: {0}")]
    CardDeclined(String),
    
    #[error("Insufficient funds")]
    InsufficientFunds,
    
    #[error("Invalid amount")]
    InvalidAmount,
    
    #[error("Provider error: {0}")]
    ProviderError(String),
    
    #[error("Refund failed: {0}")]
    RefundFailed(String),
}

pub type Result<T> = std::result::Result<T, PaymentError>;
