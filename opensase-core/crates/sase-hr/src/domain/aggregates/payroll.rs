//! Payroll Run Aggregate
//!
//! Rich aggregate for payroll processing.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;
use uuid::Uuid;

use crate::domain::events::{DomainEvent, PayrollEvent};

/// Payroll run aggregate root
#[derive(Clone, Debug)]
pub struct PayrollRun {
    id: String,
    pay_period_start: NaiveDate,
    pay_period_end: NaiveDate,
    check_date: NaiveDate,
    status: PayrollStatus,
    payslips: Vec<Payslip>,
    totals: PayrollTotals,
    created_at: DateTime<Utc>,
    processed_at: Option<DateTime<Utc>>,
    approved_by: Option<String>,
    events: Vec<DomainEvent>,
}

#[derive(Clone, Debug, Default)]
pub struct PayrollTotals {
    pub employee_count: u32,
    pub gross_pay: Decimal,
    pub net_pay: Decimal,
    pub total_taxes: Decimal,
    pub total_deductions: Decimal,
    pub employer_taxes: Decimal,
    pub employer_contributions: Decimal,
}

#[derive(Clone, Debug)]
pub struct Payslip {
    pub id: String,
    pub employee_id: String,
    pub employee_name: String,
    pub gross_pay: Decimal,
    pub earnings: Vec<EarningLine>,
    pub deductions: Vec<DeductionLine>,
    pub taxes: Vec<TaxLine>,
    pub net_pay: Decimal,
    pub status: PayslipStatus,
}

#[derive(Clone, Debug)]
pub struct EarningLine {
    pub earning_type: EarningType,
    pub hours: Option<Decimal>,
    pub rate: Option<Decimal>,
    pub amount: Decimal,
}

#[derive(Clone, Debug)]
pub enum EarningType {
    Regular,
    Overtime,
    Bonus,
    Commission,
    PTO,
    Holiday,
    Sick,
}

#[derive(Clone, Debug)]
pub struct DeductionLine {
    pub deduction_type: DeductionType,
    pub amount: Decimal,
    pub is_pretax: bool,
}

#[derive(Clone, Debug)]
pub enum DeductionType {
    Medical,
    Dental,
    Vision,
    Retirement401k,
    HSA,
    FSA,
    LifeInsurance,
    Garnishment,
    Other(String),
}

#[derive(Clone, Debug)]
pub struct TaxLine {
    pub tax_type: TaxType,
    pub amount: Decimal,
    pub ytd_amount: Decimal,
}

#[derive(Clone, Debug)]
pub enum TaxType {
    FederalIncome,
    StateIncome,
    LocalIncome,
    SocialSecurity,
    Medicare,
    FUTA,
    SUTA,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PayrollStatus {
    #[default]
    Draft,
    Pending,
    Approved,
    Processing,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PayslipStatus {
    #[default]
    Pending,
    Calculated,
    Approved,
    Paid,
    Voided,
}

impl PayrollRun {
    /// Create a new payroll run
    pub fn create(
        pay_period_start: NaiveDate,
        pay_period_end: NaiveDate,
        check_date: NaiveDate,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        
        Self {
            id,
            pay_period_start,
            pay_period_end,
            check_date,
            status: PayrollStatus::Draft,
            payslips: vec![],
            totals: PayrollTotals::default(),
            created_at: Utc::now(),
            processed_at: None,
            approved_by: None,
            events: vec![],
        }
    }
    
    // Getters
    pub fn id(&self) -> &str { &self.id }
    pub fn status(&self) -> &PayrollStatus { &self.status }
    pub fn pay_period(&self) -> (NaiveDate, NaiveDate) { (self.pay_period_start, self.pay_period_end) }
    pub fn check_date(&self) -> NaiveDate { self.check_date }
    pub fn payslips(&self) -> &[Payslip] { &self.payslips }
    pub fn totals(&self) -> &PayrollTotals { &self.totals }
    
    /// Add a payslip to the run
    pub fn add_payslip(&mut self, payslip: Payslip) -> Result<(), PayrollError> {
        if self.status != PayrollStatus::Draft {
            return Err(PayrollError::CannotModify);
        }
        
        self.payslips.push(payslip);
        self.recalculate_totals();
        Ok(())
    }
    
    /// Calculate payroll
    pub fn calculate(&mut self) -> Result<(), PayrollError> {
        if self.status != PayrollStatus::Draft {
            return Err(PayrollError::CannotModify);
        }
        
        if self.payslips.is_empty() {
            return Err(PayrollError::NoEmployees);
        }
        
        // Mark all payslips as calculated
        for payslip in &mut self.payslips {
            payslip.status = PayslipStatus::Calculated;
        }
        
        self.recalculate_totals();
        self.status = PayrollStatus::Pending;
        
        Ok(())
    }
    
    /// Approve payroll
    pub fn approve(&mut self, approver_id: impl Into<String>) -> Result<(), PayrollError> {
        if self.status != PayrollStatus::Pending {
            return Err(PayrollError::NotPending);
        }
        
        self.status = PayrollStatus::Approved;
        self.approved_by = Some(approver_id.into());
        
        for payslip in &mut self.payslips {
            payslip.status = PayslipStatus::Approved;
        }
        
        self.raise_event(DomainEvent::Payroll(PayrollEvent::Approved {
            payroll_id: self.id.clone(),
            employee_count: self.totals.employee_count,
            total_amount: self.totals.net_pay,
        }));
        
        Ok(())
    }
    
    /// Process payroll (execute payments)
    pub fn process(&mut self) -> Result<(), PayrollError> {
        if self.status != PayrollStatus::Approved {
            return Err(PayrollError::NotApproved);
        }
        
        self.status = PayrollStatus::Processing;
        Ok(())
    }
    
    /// Complete payroll
    pub fn complete(&mut self) -> Result<(), PayrollError> {
        if self.status != PayrollStatus::Processing {
            return Err(PayrollError::InvalidStatus);
        }
        
        self.status = PayrollStatus::Completed;
        self.processed_at = Some(Utc::now());
        
        for payslip in &mut self.payslips {
            payslip.status = PayslipStatus::Paid;
        }
        
        self.raise_event(DomainEvent::Payroll(PayrollEvent::Completed {
            payroll_id: self.id.clone(),
            check_date: self.check_date,
            total_disbursed: self.totals.net_pay,
        }));
        
        Ok(())
    }
    
    /// Void a payslip
    pub fn void_payslip(&mut self, payslip_id: &str) -> Result<(), PayrollError> {
        if self.status == PayrollStatus::Completed {
            return Err(PayrollError::AlreadyCompleted);
        }
        
        if let Some(payslip) = self.payslips.iter_mut().find(|p| p.id == payslip_id) {
            payslip.status = PayslipStatus::Voided;
            self.recalculate_totals();
            Ok(())
        } else {
            Err(PayrollError::PayslipNotFound)
        }
    }
    
    fn recalculate_totals(&mut self) {
        let active: Vec<&Payslip> = self.payslips.iter()
            .filter(|p| p.status != PayslipStatus::Voided)
            .collect();
        
        self.totals = PayrollTotals {
            employee_count: active.len() as u32,
            gross_pay: active.iter().map(|p| p.gross_pay).sum(),
            net_pay: active.iter().map(|p| p.net_pay).sum(),
            total_taxes: active.iter().flat_map(|p| &p.taxes).map(|t| t.amount).sum(),
            total_deductions: active.iter().flat_map(|p| &p.deductions).map(|d| d.amount).sum(),
            employer_taxes: Decimal::ZERO, // Would calculate FICA, FUTA, SUTA
            employer_contributions: Decimal::ZERO,
        };
    }
    
    pub fn take_events(&mut self) -> Vec<DomainEvent> {
        std::mem::take(&mut self.events)
    }
    
    fn raise_event(&mut self, event: DomainEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayrollError {
    CannotModify,
    NoEmployees,
    NotPending,
    NotApproved,
    InvalidStatus,
    AlreadyCompleted,
    PayslipNotFound,
}

impl std::error::Error for PayrollError {}
impl std::fmt::Display for PayrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CannotModify => write!(f, "Cannot modify payroll in current status"),
            Self::NoEmployees => write!(f, "No employees in payroll"),
            Self::NotPending => write!(f, "Payroll is not pending"),
            Self::NotApproved => write!(f, "Payroll is not approved"),
            Self::InvalidStatus => write!(f, "Invalid payroll status"),
            Self::AlreadyCompleted => write!(f, "Payroll already completed"),
            Self::PayslipNotFound => write!(f, "Payslip not found"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_payslip(employee_id: &str) -> Payslip {
        Payslip {
            id: Uuid::new_v4().to_string(),
            employee_id: employee_id.to_string(),
            employee_name: "Test Employee".to_string(),
            gross_pay: Decimal::new(5000, 0),
            earnings: vec![EarningLine {
                earning_type: EarningType::Regular,
                hours: Some(Decimal::new(80, 0)),
                rate: Some(Decimal::new(6250, 2)),
                amount: Decimal::new(5000, 0),
            }],
            deductions: vec![],
            taxes: vec![TaxLine {
                tax_type: TaxType::FederalIncome,
                amount: Decimal::new(750, 0),
                ytd_amount: Decimal::new(9000, 0),
            }],
            net_pay: Decimal::new(4250, 0),
            status: PayslipStatus::Pending,
        }
    }
    
    #[test]
    fn test_payroll_creation() {
        let payroll = PayrollRun::create(
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 20).unwrap(),
        );
        assert_eq!(payroll.status(), &PayrollStatus::Draft);
    }
    
    #[test]
    fn test_payroll_workflow() {
        let mut payroll = PayrollRun::create(
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 20).unwrap(),
        );
        
        payroll.add_payslip(create_test_payslip("EMP001")).unwrap();
        payroll.calculate().unwrap();
        assert_eq!(payroll.status(), &PayrollStatus::Pending);
        
        payroll.approve("ADMIN001").unwrap();
        assert_eq!(payroll.status(), &PayrollStatus::Approved);
        
        payroll.process().unwrap();
        payroll.complete().unwrap();
        assert_eq!(payroll.status(), &PayrollStatus::Completed);
    }
}
