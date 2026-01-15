//! Domain services

/// Payroll calculation service
pub struct PayrollCalculator;

impl PayrollCalculator {
    /// Calculate federal income tax (simplified)
    pub fn calculate_federal_tax(gross_pay: rust_decimal::Decimal, filing_status: &str) -> rust_decimal::Decimal {
        use rust_decimal::Decimal;
        // Simplified progressive tax brackets
        let rate = match filing_status {
            "single" => {
                if gross_pay > Decimal::new(10000, 0) { Decimal::new(22, 2) }
                else if gross_pay > Decimal::new(5000, 0) { Decimal::new(12, 2) }
                else { Decimal::new(10, 2) }
            },
            _ => Decimal::new(12, 2),
        };
        gross_pay * rate
    }
    
    /// Calculate FICA (Social Security + Medicare)
    pub fn calculate_fica(gross_pay: rust_decimal::Decimal) -> (rust_decimal::Decimal, rust_decimal::Decimal) {
        use rust_decimal::Decimal;
        let ss = gross_pay * Decimal::new(62, 3);  // 6.2%
        let medicare = gross_pay * Decimal::new(145, 4); // 1.45%
        (ss, medicare)
    }
}

/// Time tracking service
pub struct TimeTrackingCalculator;

impl TimeTrackingCalculator {
    /// Calculate overtime hours (over 40 hours)
    pub fn calculate_overtime(hours_worked: rust_decimal::Decimal) -> rust_decimal::Decimal {
        use rust_decimal::Decimal;
        let threshold = Decimal::new(40, 0);
        if hours_worked > threshold {
            hours_worked - threshold
        } else {
            Decimal::ZERO
        }
    }
}
