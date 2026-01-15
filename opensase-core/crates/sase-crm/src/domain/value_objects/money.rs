//! Money Value Object
//!
//! Immutable monetary value with currency, following DDD principles.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Sub, Mul};

/// Money value object with currency
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    amount: Decimal,
    currency: Currency,
}

impl Money {
    /// Create a new money value
    pub fn new(amount: Decimal, currency: Currency) -> Self {
        Self { amount, currency }
    }
    
    /// Create money from i64 cents
    pub fn from_cents(cents: i64, currency: Currency) -> Self {
        let amount = Decimal::new(cents, 2);
        Self { amount, currency }
    }
    
    /// Create zero money
    pub fn zero(currency: Currency) -> Self {
        Self {
            amount: Decimal::ZERO,
            currency,
        }
    }
    
    /// Create USD money
    pub fn usd(amount: Decimal) -> Self {
        Self::new(amount, Currency::USD)
    }
    
    /// Get the amount
    pub fn amount(&self) -> Decimal {
        self.amount
    }
    
    /// Get the currency
    pub fn currency(&self) -> &Currency {
        &self.currency
    }
    
    /// Check if same currency
    pub fn same_currency(&self, other: &Money) -> bool {
        self.currency == other.currency
    }
    
    /// Add money (must be same currency)
    pub fn add(&self, other: &Money) -> Result<Money, MoneyError> {
        if !self.same_currency(other) {
            return Err(MoneyError::CurrencyMismatch);
        }
        Ok(Money::new(self.amount + other.amount, self.currency.clone()))
    }
    
    /// Subtract money (must be same currency)
    pub fn subtract(&self, other: &Money) -> Result<Money, MoneyError> {
        if !self.same_currency(other) {
            return Err(MoneyError::CurrencyMismatch);
        }
        Ok(Money::new(self.amount - other.amount, self.currency.clone()))
    }
    
    /// Multiply by a factor
    pub fn multiply(&self, factor: Decimal) -> Money {
        Money::new(self.amount * factor, self.currency.clone())
    }
    
    /// Check if positive
    pub fn is_positive(&self) -> bool {
        self.amount > Decimal::ZERO
    }
    
    /// Check if negative
    pub fn is_negative(&self) -> bool {
        self.amount < Decimal::ZERO
    }
    
    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.amount == Decimal::ZERO
    }
    
    /// Get absolute value
    pub fn abs(&self) -> Money {
        Money::new(self.amount.abs(), self.currency.clone())
    }
}

impl Default for Money {
    fn default() -> Self {
        Self::zero(Currency::USD)
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:.2}", self.currency, self.amount)
    }
}

/// Currency enum
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Currency {
    USD,
    EUR,
    GBP,
    CAD,
    AUD,
    NGN,
    JPY,
    CNY,
    INR,
    Other(String),
}

impl Currency {
    pub fn code(&self) -> &str {
        match self {
            Self::USD => "USD",
            Self::EUR => "EUR",
            Self::GBP => "GBP",
            Self::CAD => "CAD",
            Self::AUD => "AUD",
            Self::NGN => "NGN",
            Self::JPY => "JPY",
            Self::CNY => "CNY",
            Self::INR => "INR",
            Self::Other(code) => code,
        }
    }
    
    pub fn from_code(code: &str) -> Self {
        match code.to_uppercase().as_str() {
            "USD" => Self::USD,
            "EUR" => Self::EUR,
            "GBP" => Self::GBP,
            "CAD" => Self::CAD,
            "AUD" => Self::AUD,
            "NGN" => Self::NGN,
            "JPY" => Self::JPY,
            "CNY" => Self::CNY,
            "INR" => Self::INR,
            other => Self::Other(other.to_string()),
        }
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl Default for Currency {
    fn default() -> Self {
        Self::USD
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoneyError {
    CurrencyMismatch,
    NegativeAmount,
}

impl std::error::Error for MoneyError {}

impl fmt::Display for MoneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrencyMismatch => write!(f, "Currency mismatch"),
            Self::NegativeAmount => write!(f, "Amount cannot be negative"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_money_creation() {
        let money = Money::usd(Decimal::new(1000, 2)); // $10.00
        assert_eq!(money.amount(), Decimal::new(1000, 2));
        assert_eq!(money.currency(), &Currency::USD);
    }
    
    #[test]
    fn test_money_from_cents() {
        let money = Money::from_cents(1050, Currency::USD);
        assert_eq!(money.amount(), Decimal::new(1050, 2)); // $10.50
    }
    
    #[test]
    fn test_money_add() {
        let a = Money::usd(Decimal::new(1000, 2));
        let b = Money::usd(Decimal::new(500, 2));
        let sum = a.add(&b).unwrap();
        assert_eq!(sum.amount(), Decimal::new(1500, 2));
    }
    
    #[test]
    fn test_money_currency_mismatch() {
        let usd = Money::usd(Decimal::new(1000, 2));
        let eur = Money::new(Decimal::new(500, 2), Currency::EUR);
        assert!(matches!(usd.add(&eur), Err(MoneyError::CurrencyMismatch)));
    }
    
    #[test]
    fn test_money_multiply() {
        let money = Money::usd(Decimal::new(1000, 2));
        let result = money.multiply(Decimal::new(15, 1)); // 1.5
        assert_eq!(result.amount(), Decimal::new(1500, 2));
    }
}
