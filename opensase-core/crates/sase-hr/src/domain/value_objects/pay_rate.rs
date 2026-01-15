//! Pay Rate value object

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Pay rate with type and frequency
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayRate {
    amount: Decimal,
    currency: String,
    pay_type: PayType,
    frequency: PayFrequency,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayType {
    Salary,
    Hourly,
    Commission,
    Contract,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayFrequency {
    Weekly,
    BiWeekly,
    SemiMonthly,
    Monthly,
    Annually,
}

impl PayRate {
    pub fn salary(amount: Decimal, currency: &str, frequency: PayFrequency) -> Self {
        Self {
            amount,
            currency: currency.to_string(),
            pay_type: PayType::Salary,
            frequency,
        }
    }
    
    pub fn hourly(rate: Decimal, currency: &str) -> Self {
        Self {
            amount: rate,
            currency: currency.to_string(),
            pay_type: PayType::Hourly,
            frequency: PayFrequency::BiWeekly, // Default for hourly
        }
    }
    
    pub fn amount(&self) -> Decimal { self.amount }
    pub fn currency(&self) -> &str { &self.currency }
    pub fn pay_type(&self) -> &PayType { &self.pay_type }
    pub fn frequency(&self) -> &PayFrequency { &self.frequency }
    
    /// Calculate annual salary
    pub fn annual_amount(&self) -> Decimal {
        match self.frequency {
            PayFrequency::Annually => self.amount,
            PayFrequency::Monthly => self.amount * Decimal::from(12),
            PayFrequency::SemiMonthly => self.amount * Decimal::from(24),
            PayFrequency::BiWeekly => self.amount * Decimal::from(26),
            PayFrequency::Weekly => self.amount * Decimal::from(52),
        }
    }
    
    /// Calculate per-period amount from annual
    pub fn per_period(&self, periods_per_year: u32) -> Decimal {
        self.annual_amount() / Decimal::from(periods_per_year)
    }
}

impl fmt::Display for PayRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:.2}/{:?}", self.currency, self.amount, self.frequency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_annual_calculation() {
        let rate = PayRate::salary(
            Decimal::new(5000, 0),
            "USD",
            PayFrequency::Monthly,
        );
        assert_eq!(rate.annual_amount(), Decimal::new(60000, 0));
    }
}
