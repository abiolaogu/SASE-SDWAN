//! OpenSASE HR & Payroll Platform
//!
//! Self-hosted HR platform replacing BambooHR, Gusto, Workday, ADP.
//!
//! ## Features
//! - Employee lifecycle management
//! - Payroll processing with tax calculations
//! - Benefits administration
//! - Time and attendance tracking
//! - Performance reviews

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Employee {
    pub id: String,
    pub employee_number: String,
    pub status: EmploymentStatus,
    pub personal: PersonalInfo,
    pub employment: EmploymentInfo,
    pub compensation: CompensationInfo,
    pub emergency_contacts: Vec<EmergencyContact>,
    pub custom_fields: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PersonalInfo {
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub preferred_name: Option<String>,
    pub date_of_birth: Option<NaiveDate>,
    pub gender: Option<String>,
    pub personal_email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Address {
    pub street1: String,
    pub street2: Option<String>,
    pub city: String,
    pub state: Option<String>,
    pub postal_code: String,
    pub country: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EmploymentInfo {
    pub hire_date: Option<NaiveDate>,
    pub termination_date: Option<NaiveDate>,
    pub employment_type: EmploymentType,
    pub job_title: String,
    pub department_id: Option<String>,
    pub manager_id: Option<String>,
    pub work_email: String,
    pub work_phone: Option<String>,
    pub location_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum EmploymentStatus {
    #[default]
    Active,
    OnLeave,
    Suspended,
    Terminated,
    Retired,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum EmploymentType {
    #[default]
    FullTime,
    PartTime,
    Contractor,
    Intern,
    Temporary,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CompensationInfo {
    pub pay_type: PayType,
    pub pay_rate: Decimal,
    pub currency: String,
    pub pay_frequency: PayFrequency,
    pub effective_date: Option<NaiveDate>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum PayType {
    #[default]
    Salary,
    Hourly,
    Commission,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum PayFrequency {
    Weekly,
    #[default]
    BiWeekly,
    SemiMonthly,
    Monthly,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EmergencyContact {
    pub name: String,
    pub relationship: String,
    pub phone: String,
    pub email: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayrollRun {
    pub id: String,
    pub pay_period_start: NaiveDate,
    pub pay_period_end: NaiveDate,
    pub check_date: NaiveDate,
    pub status: PayrollStatus,
    pub employee_count: u32,
    pub gross_total: Decimal,
    pub net_total: Decimal,
    pub taxes_total: Decimal,
    pub created_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum PayrollStatus {
    #[default]
    Draft,
    Pending,
    Approved,
    Processing,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeEntry {
    pub id: String,
    pub employee_id: String,
    pub date: NaiveDate,
    pub clock_in: Option<DateTime<Utc>>,
    pub clock_out: Option<DateTime<Utc>>,
    pub hours_worked: Decimal,
    pub overtime_hours: Decimal,
    pub entry_type: TimeEntryType,
    pub approved: bool,
    pub approved_by: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum TimeEntryType {
    #[default]
    Regular,
    Overtime,
    PTO,
    Sick,
    Holiday,
    Unpaid,
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum HrError {
    #[error("Employee not found")]
    EmployeeNotFound,
    
    #[error("Department not found")]
    DepartmentNotFound,
    
    #[error("Payroll run not found")]
    PayrollNotFound,
    
    #[error("Invalid termination date")]
    InvalidTerminationDate,
    
    #[error("Payroll already processed")]
    PayrollAlreadyProcessed,
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, HrError>;
