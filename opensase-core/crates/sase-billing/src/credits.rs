//! Credits & Promotions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Credit manager
pub struct CreditManager {
    credits: Arc<RwLock<HashMap<Uuid, Credit>>>,
    promo_codes: Arc<RwLock<HashMap<String, PromoCode>>>,
}

impl CreditManager {
    pub fn new() -> Self {
        Self {
            credits: Arc::new(RwLock::new(HashMap::new())),
            promo_codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add credit
    pub fn add_credit(&self, credit: Credit) -> Uuid {
        let id = credit.id;
        self.credits.write().insert(id, credit);
        id
    }

    /// Get available credits for tenant (sorted by expiration - oldest first)
    pub fn get_available(&self, tenant_id: Uuid) -> Vec<Credit> {
        let now = Utc::now();
        let mut credits: Vec<_> = self.credits.read()
            .values()
            .filter(|c| {
                c.tenant_id == tenant_id && 
                c.remaining_amount > dec!(0) &&
                c.expires_at.map(|e| e > now).unwrap_or(true)
            })
            .cloned()
            .collect();

        // Sort by expiration (oldest first)
        credits.sort_by(|a, b| {
            match (&a.expires_at, &b.expires_at) {
                (Some(a_exp), Some(b_exp)) => a_exp.cmp(b_exp),
                (Some(_), None) => std::cmp::Ordering::Less, // Expiring before non-expiring
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.created_at.cmp(&b.created_at),
            }
        });

        credits
    }

    /// Apply credit
    pub fn apply_credit(&self, credit_id: Uuid, amount: Decimal) -> Result<Decimal, CreditError> {
        let mut credits = self.credits.write();
        let credit = credits.get_mut(&credit_id).ok_or(CreditError::NotFound)?;

        if credit.remaining_amount < amount {
            return Err(CreditError::InsufficientBalance);
        }

        credit.remaining_amount -= amount;
        credit.used_amount += amount;

        Ok(credit.remaining_amount)
    }

    /// Issue sign-up credit
    pub fn issue_signup_credit(&self, tenant_id: Uuid, amount: Decimal) -> Uuid {
        let credit = Credit {
            id: Uuid::new_v4(),
            tenant_id,
            credit_type: CreditType::SignUp,
            description: "Welcome credit".into(),
            original_amount: amount,
            remaining_amount: amount,
            used_amount: dec!(0),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            created_at: Utc::now(),
        };
        self.add_credit(credit)
    }

    /// Issue referral credit
    pub fn issue_referral_credit(&self, referrer_id: Uuid, referred_id: Uuid, amount: Decimal) -> (Uuid, Uuid) {
        let referrer_credit = Credit {
            id: Uuid::new_v4(),
            tenant_id: referrer_id,
            credit_type: CreditType::Referral,
            description: format!("Referral bonus for tenant {}", referred_id),
            original_amount: amount,
            remaining_amount: amount,
            used_amount: dec!(0),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            created_at: Utc::now(),
        };
        let referrer_id = self.add_credit(referrer_credit);

        let referred_credit = Credit {
            id: Uuid::new_v4(),
            tenant_id: referred_id,
            credit_type: CreditType::Referral,
            description: "Referral welcome credit".into(),
            original_amount: amount / dec!(2),
            remaining_amount: amount / dec!(2),
            used_amount: dec!(0),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            created_at: Utc::now(),
        };
        let referred_credit_id = self.add_credit(referred_credit);

        (referrer_id, referred_credit_id)
    }

    /// Create promo code
    pub fn create_promo_code(&self, code: &str, promo: PromoCode) {
        self.promo_codes.write().insert(code.to_uppercase(), promo);
    }

    /// Validate and apply promo code
    pub fn apply_promo_code(&self, code: &str, tenant_id: Uuid) -> Result<PromoResult, CreditError> {
        let discount_type = {
            let mut codes = self.promo_codes.write();
            let promo = codes.get_mut(&code.to_uppercase())
                .ok_or(CreditError::InvalidCode)?;

            // Check if expired
            if let Some(exp) = promo.expires_at {
                if exp < Utc::now() {
                    return Err(CreditError::ExpiredCode);
                }
            }

            // Check redemption limit
            if let Some(limit) = promo.max_redemptions {
                if promo.redemptions >= limit {
                    return Err(CreditError::CodeLimitReached);
                }
            }

            // Apply the promo
            promo.redemptions += 1;
            promo.discount_type.clone()
        }; // Lock dropped here

        match &discount_type {
            DiscountType::Percentage(pct) => {
                Ok(PromoResult::Percentage(*pct))
            }
            DiscountType::FixedAmount(amt) => {
                // Create a credit for fixed amount
                let credit = Credit {
                    id: Uuid::new_v4(),
                    tenant_id,
                    credit_type: CreditType::Promotion,
                    description: format!("Promo code: {}", code),
                    original_amount: *amt,
                    remaining_amount: *amt,
                    used_amount: dec!(0),
                    expires_at: Some(Utc::now() + chrono::Duration::days(90)),
                    created_at: Utc::now(),
                };
                self.add_credit(credit);
                Ok(PromoResult::Credit(*amt))
            }
            DiscountType::FreeTrial(days) => {
                Ok(PromoResult::FreeTrial(*days))
            }
        }
    }
}

impl Default for CreditManager {
    fn default() -> Self { Self::new() }
}

/// Credit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credit {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub credit_type: CreditType,
    pub description: String,
    pub original_amount: Decimal,
    pub remaining_amount: Decimal,
    pub used_amount: Decimal,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Credit {
    pub fn is_active(&self) -> bool {
        self.remaining_amount > dec!(0) &&
        self.expires_at.map(|e| e > Utc::now()).unwrap_or(true)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CreditType {
    SignUp,
    Referral,
    Compensation,
    Partner,
    Promotion,
}

/// Promo code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoCode {
    pub code: String,
    pub description: String,
    pub discount_type: DiscountType,
    pub max_redemptions: Option<u32>,
    pub redemptions: u32,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscountType {
    Percentage(Decimal),
    FixedAmount(Decimal),
    FreeTrial(u32), // days
}

/// Promo result
#[derive(Debug, Clone)]
pub enum PromoResult {
    Percentage(Decimal),
    Credit(Decimal),
    FreeTrial(u32),
}

/// Credit error
#[derive(Debug, Clone)]
pub enum CreditError {
    NotFound,
    InsufficientBalance,
    InvalidCode,
    ExpiredCode,
    CodeLimitReached,
}

impl std::fmt::Display for CreditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Credit not found"),
            Self::InsufficientBalance => write!(f, "Insufficient credit balance"),
            Self::InvalidCode => write!(f, "Invalid promo code"),
            Self::ExpiredCode => write!(f, "Promo code expired"),
            Self::CodeLimitReached => write!(f, "Promo code redemption limit reached"),
        }
    }
}
