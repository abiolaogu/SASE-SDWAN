//! Payment Processing (Stripe Integration)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rust_decimal::Decimal;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Payment processor (Stripe-based)
pub struct PaymentProcessor {
    /// Payment methods per tenant
    methods: Arc<RwLock<HashMap<Uuid, Vec<PaymentMethod>>>>,
    /// Payments
    payments: Arc<RwLock<HashMap<Uuid, Payment>>>,
    /// Dunning state
    dunning: Arc<RwLock<HashMap<Uuid, DunningState>>>,
}

impl PaymentProcessor {
    pub fn new() -> Self {
        Self {
            methods: Arc::new(RwLock::new(HashMap::new())),
            payments: Arc::new(RwLock::new(HashMap::new())),
            dunning: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add payment method
    pub fn add_payment_method(&self, tenant_id: Uuid, method: PaymentMethod) -> Uuid {
        let id = method.id;
        self.methods.write()
            .entry(tenant_id)
            .or_default()
            .push(method);
        id
    }

    /// Get payment methods for tenant
    pub fn get_payment_methods(&self, tenant_id: Uuid) -> Vec<PaymentMethod> {
        self.methods.read()
            .get(&tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get default payment method
    pub fn get_default_method(&self, tenant_id: Uuid) -> Option<PaymentMethod> {
        self.methods.read()
            .get(&tenant_id)?
            .iter()
            .find(|m| m.is_default)
            .cloned()
    }

    /// Process payment
    pub async fn process_payment(
        &self,
        tenant_id: Uuid,
        invoice_id: Uuid,
        amount: Decimal,
    ) -> Result<Payment, PaymentError> {
        let method = self.get_default_method(tenant_id)
            .ok_or(PaymentError::NoPaymentMethod)?;

        // In production: call Stripe API
        let payment = Payment {
            id: Uuid::new_v4(),
            tenant_id,
            invoice_id,
            amount,
            currency: "USD".into(),
            status: PaymentStatus::Succeeded, // Simulated
            payment_method_id: method.id,
            stripe_payment_intent_id: Some(format!("pi_{}", Uuid::new_v4().to_string().replace("-", ""))),
            created_at: Utc::now(),
            error: None,
        };

        self.payments.write().insert(payment.id, payment.clone());
        self.clear_dunning(tenant_id);

        Ok(payment)
    }

    /// Retry failed payment
    pub async fn retry_payment(&self, payment_id: Uuid) -> Result<Payment, PaymentError> {
        let payment = self.payments.read()
            .get(&payment_id)
            .cloned()
            .ok_or(PaymentError::PaymentNotFound)?;

        if payment.status != PaymentStatus::Failed {
            return Err(PaymentError::InvalidState);
        }

        // In production: retry with Stripe
        let mut updated = payment;
        updated.status = PaymentStatus::Succeeded;
        self.payments.write().insert(updated.id, updated.clone());

        Ok(updated)
    }

    /// Handle failed payment (dunning)
    pub fn handle_failure(&self, tenant_id: Uuid, invoice_id: Uuid) {
        let mut dunning = self.dunning.write();
        let state = dunning.entry(tenant_id).or_insert_with(|| DunningState {
            tenant_id,
            invoice_id,
            attempts: 0,
            next_attempt: Utc::now() + chrono::Duration::days(1),
            emails_sent: vec![],
            status: DunningStatus::Active,
        });

        state.attempts += 1;
        state.next_attempt = Utc::now() + chrono::Duration::days(2_i64.pow(state.attempts.min(5)));

        // Determine email to send
        let email_type = match state.attempts {
            1 => DunningEmailType::FirstReminder,
            2 => DunningEmailType::SecondReminder,
            3 => DunningEmailType::FinalWarning,
            _ => DunningEmailType::AccountSuspension,
        };

        state.emails_sent.push(DunningEmail {
            email_type,
            sent_at: Utc::now(),
        });

        if state.attempts >= 4 {
            state.status = DunningStatus::Exhausted;
            // Trigger account suspension
        }
    }

    fn clear_dunning(&self, tenant_id: Uuid) {
        self.dunning.write().remove(&tenant_id);
    }

    /// Get payment history
    pub fn get_payments(&self, tenant_id: Uuid) -> Vec<Payment> {
        self.payments.read()
            .values()
            .filter(|p| p.tenant_id == tenant_id)
            .cloned()
            .collect()
    }
}

impl Default for PaymentProcessor {
    fn default() -> Self { Self::new() }
}

/// Payment method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethod {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub method_type: PaymentMethodType,
    pub is_default: bool,
    pub last_four: String,
    pub exp_month: u8,
    pub exp_year: u16,
    pub brand: Option<String>,
    pub stripe_payment_method_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PaymentMethodType {
    Card,
    BankAccount,
    Invoice,
}

/// Payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub invoice_id: Uuid,
    pub amount: Decimal,
    pub currency: String,
    pub status: PaymentStatus,
    pub payment_method_id: Uuid,
    pub stripe_payment_intent_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    Pending,
    Processing,
    Succeeded,
    Failed,
    Refunded,
}

/// Payment error
#[derive(Debug, Clone)]
pub enum PaymentError {
    NoPaymentMethod,
    PaymentNotFound,
    InvalidState,
    StripeError(String),
    Declined(String),
}

impl std::fmt::Display for PaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPaymentMethod => write!(f, "No payment method on file"),
            Self::PaymentNotFound => write!(f, "Payment not found"),
            Self::InvalidState => write!(f, "Invalid payment state"),
            Self::StripeError(e) => write!(f, "Stripe error: {}", e),
            Self::Declined(r) => write!(f, "Payment declined: {}", r),
        }
    }
}

/// Dunning state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DunningState {
    pub tenant_id: Uuid,
    pub invoice_id: Uuid,
    pub attempts: u32,
    pub next_attempt: DateTime<Utc>,
    pub emails_sent: Vec<DunningEmail>,
    pub status: DunningStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DunningStatus {
    Active,
    Exhausted,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DunningEmail {
    pub email_type: DunningEmailType,
    pub sent_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DunningEmailType {
    FirstReminder,
    SecondReminder,
    FinalWarning,
    AccountSuspension,
}
