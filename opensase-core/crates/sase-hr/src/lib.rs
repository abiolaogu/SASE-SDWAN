//! OpenSASE HR & Payroll Platform
//!
//! Enterprise-grade HR platform following DDD/XP principles.
//! Replaces BambooHR, Gusto, Workday, ADP.
//!
//! ## Key Aggregates
//!
//! - **Employee**: Full lifecycle management
//! - **PayrollRun**: Payroll processing workflow
//!
//! ## Features
//!
//! - Employee onboarding and offboarding
//! - Payroll processing with tax calculations
//! - Benefits administration
//! - Time and attendance tracking

pub mod domain;

// Re-exports
pub use domain::aggregates::{Employee, EmployeeError, PayrollRun, PayrollError};
pub use domain::value_objects::{EmployeeId, TaxId, PayRate, PayType, PayFrequency};
pub use domain::events::{DomainEvent, EmployeeEvent, PayrollEvent};
