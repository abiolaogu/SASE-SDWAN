//! Value Objects for HR domain

pub mod employee_id;
pub mod tax_id;
pub mod pay_rate;

pub use employee_id::EmployeeId;
pub use tax_id::{TaxId, TaxIdType, TaxIdError};
pub use pay_rate::{PayRate, PayType, PayFrequency};

