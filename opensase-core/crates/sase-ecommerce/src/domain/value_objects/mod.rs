//! Value Objects for E-commerce

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;

/// SKU (Stock Keeping Unit) value object
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sku(String);

impl Sku {
    pub fn new(value: impl Into<String>) -> Result<Self, SkuError> {
        let value = value.into().trim().to_uppercase();
        if value.is_empty() { return Err(SkuError::Empty); }
        if value.len() > 50 { return Err(SkuError::TooLong); }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for Sku {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

#[derive(Debug, Clone)] pub enum SkuError { Empty, TooLong }
impl std::error::Error for SkuError {}
impl fmt::Display for SkuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Empty => write!(f, "SKU empty"), Self::TooLong => write!(f, "SKU too long") }
    }
}

/// Money value object
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money { amount: Decimal, currency: String }

impl Money {
    pub fn new(amount: Decimal, currency: &str) -> Self { Self { amount, currency: currency.to_string() } }
    pub fn usd(amount: Decimal) -> Self { Self::new(amount, "USD") }
    pub fn zero(currency: &str) -> Self { Self::new(Decimal::ZERO, currency) }
    pub fn amount(&self) -> Decimal { self.amount }
    pub fn currency(&self) -> &str { &self.currency }
    pub fn add(&self, other: &Money) -> Result<Money, MoneyError> {
        if self.currency != other.currency { return Err(MoneyError::CurrencyMismatch); }
        Ok(Money::new(self.amount + other.amount, &self.currency))
    }
    pub fn multiply(&self, qty: u32) -> Money { Money::new(self.amount * Decimal::from(qty), &self.currency) }
}

impl Default for Money { fn default() -> Self { Self::zero("USD") } }

#[derive(Debug, Clone)] pub enum MoneyError { CurrencyMismatch }
impl std::error::Error for MoneyError {}
impl fmt::Display for MoneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Currency mismatch") }
}

/// Quantity value object
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quantity(u32);

impl Quantity {
    pub fn new(value: u32) -> Self { Self(value) }
    pub fn value(&self) -> u32 { self.0 }
    pub fn add(&self, other: u32) -> Self { Self(self.0.saturating_add(other)) }
    pub fn subtract(&self, other: u32) -> Option<Self> {
        if other > self.0 { None } else { Some(Self(self.0 - other)) }
    }
    pub fn is_zero(&self) -> bool { self.0 == 0 }
}

impl Default for Quantity { fn default() -> Self { Self(0) } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sku() { let sku = Sku::new("prod-001").unwrap(); assert_eq!(sku.as_str(), "PROD-001"); }
    #[test]
    fn test_money_add() {
        let a = Money::usd(Decimal::new(100, 0));
        let b = Money::usd(Decimal::new(50, 0));
        assert_eq!(a.add(&b).unwrap().amount(), Decimal::new(150, 0));
    }
}
