//! Employee Aggregate
//!
//! Rich aggregate root for employee lifecycle management.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;
use uuid::Uuid;

use crate::domain::value_objects::{EmployeeId, TaxId, PayRate, PayType, PayFrequency};
use crate::domain::events::{DomainEvent, EmployeeEvent};

/// Employee aggregate root
#[derive(Clone, Debug)]
pub struct Employee {
    id: String,
    employee_id: EmployeeId,
    status: EmploymentStatus,
    personal: PersonalInfo,
    employment: EmploymentInfo,
    compensation: CompensationInfo,
    benefits_elections: Vec<BenefitElection>,
    emergency_contacts: Vec<EmergencyContact>,
    documents: Vec<EmployeeDocument>,
    custom_fields: HashMap<String, serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    events: Vec<DomainEvent>,
}

#[derive(Clone, Debug, Default)]
pub struct PersonalInfo {
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub preferred_name: Option<String>,
    pub date_of_birth: Option<NaiveDate>,
    pub gender: Option<String>,
    pub marital_status: Option<MaritalStatus>,
    pub personal_email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<AddressInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct AddressInfo {
    pub street1: String,
    pub street2: Option<String>,
    pub city: String,
    pub state: Option<String>,
    pub postal_code: String,
    pub country: String,
}

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug, Default)]
pub struct CompensationInfo {
    pub pay_rate: Option<PayRate>,
    pub effective_date: Option<NaiveDate>,
    pub bonus_eligible: bool,
    pub equity_grants: Vec<EquityGrant>,
    pub compensation_history: Vec<CompensationChange>,
}

#[derive(Clone, Debug)]
pub struct EquityGrant {
    pub grant_date: NaiveDate,
    pub shares: u64,
    pub vesting_schedule: VestingSchedule,
    pub strike_price: Decimal,
}

#[derive(Clone, Debug)]
pub enum VestingSchedule {
    FourYearMonthly,
    FourYearAnnual,
    ThreeYearMonthly,
    Immediate,
}

#[derive(Clone, Debug)]
pub struct CompensationChange {
    pub effective_date: NaiveDate,
    pub old_rate: Decimal,
    pub new_rate: Decimal,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct BenefitElection {
    pub benefit_plan_id: String,
    pub coverage_level: CoverageLevel,
    pub dependents: Vec<String>,
    pub enrolled_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum CoverageLevel {
    Employee,
    EmployeePlusSpouse,
    EmployeePlusChildren,
    Family,
}

#[derive(Clone, Debug, Default)]
pub struct EmergencyContact {
    pub name: String,
    pub relationship: String,
    pub phone: String,
    pub email: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EmployeeDocument {
    pub id: String,
    pub doc_type: DocumentType,
    pub name: String,
    pub uploaded_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum DocumentType {
    Resume,
    OfferLetter,
    Contract,
    TaxForm,
    IdDocument,
    Certification,
    PerformanceReview,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EmploymentStatus {
    #[default]
    Active,
    OnLeave,
    Suspended,
    Terminated,
    Retired,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EmploymentType {
    #[default]
    FullTime,
    PartTime,
    Contractor,
    Intern,
    Temporary,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum MaritalStatus {
    #[default]
    Single,
    Married,
    DomesticPartnership,
    Divorced,
    Widowed,
}

impl Employee {
    /// Create a new employee (factory method)
    pub fn hire(
        employee_id: EmployeeId,
        first_name: impl Into<String>,
        last_name: impl Into<String>,
        work_email: impl Into<String>,
        job_title: impl Into<String>,
        hire_date: NaiveDate,
    ) -> Self {
        let now = Utc::now();
        let id = Uuid::new_v4().to_string();
        
        let mut employee = Self {
            id: id.clone(),
            employee_id: employee_id.clone(),
            status: EmploymentStatus::Active,
            personal: PersonalInfo {
                first_name: first_name.into(),
                last_name: last_name.into(),
                ..Default::default()
            },
            employment: EmploymentInfo {
                hire_date: Some(hire_date),
                work_email: work_email.into(),
                job_title: job_title.into(),
                employment_type: EmploymentType::FullTime,
                ..Default::default()
            },
            compensation: CompensationInfo::default(),
            benefits_elections: vec![],
            emergency_contacts: vec![],
            documents: vec![],
            custom_fields: HashMap::new(),
            created_at: now,
            updated_at: now,
            events: vec![],
        };
        
        employee.raise_event(DomainEvent::Employee(EmployeeEvent::Hired {
            employee_id,
            hire_date,
        }));
        
        employee
    }
    
    // Getters
    pub fn id(&self) -> &str { &self.id }
    pub fn employee_id(&self) -> &EmployeeId { &self.employee_id }
    pub fn status(&self) -> &EmploymentStatus { &self.status }
    pub fn personal(&self) -> &PersonalInfo { &self.personal }
    pub fn employment(&self) -> &EmploymentInfo { &self.employment }
    pub fn compensation(&self) -> &CompensationInfo { &self.compensation }
    pub fn full_name(&self) -> String { 
        format!("{} {}", self.personal.first_name, self.personal.last_name) 
    }
    pub fn is_active(&self) -> bool { self.status == EmploymentStatus::Active }
    
    /// Set compensation
    pub fn set_compensation(&mut self, pay_rate: PayRate, effective_date: NaiveDate) {
        if let Some(old_rate) = &self.compensation.pay_rate {
            self.compensation.compensation_history.push(CompensationChange {
                effective_date,
                old_rate: old_rate.amount(),
                new_rate: pay_rate.amount(),
                reason: "Compensation update".to_string(),
            });
        }
        
        self.compensation.pay_rate = Some(pay_rate.clone());
        self.compensation.effective_date = Some(effective_date);
        self.touch();
        
        self.raise_event(DomainEvent::Employee(EmployeeEvent::CompensationChanged {
            employee_id: self.employee_id.clone(),
            new_amount: pay_rate.amount(),
            effective_date,
        }));
    }
    
    /// Promote employee
    pub fn promote(&mut self, new_title: impl Into<String>, new_rate: Option<PayRate>) {
        let old_title = self.employment.job_title.clone();
        self.employment.job_title = new_title.into();
        
        if let Some(rate) = new_rate {
            self.set_compensation(rate, chrono::Utc::now().date_naive());
        }
        
        self.touch();
        
        self.raise_event(DomainEvent::Employee(EmployeeEvent::Promoted {
            employee_id: self.employee_id.clone(),
            old_title,
            new_title: self.employment.job_title.clone(),
        }));
    }
    
    /// Transfer to new department/manager
    pub fn transfer(&mut self, department_id: Option<String>, manager_id: Option<String>) {
        self.employment.department_id = department_id;
        self.employment.manager_id = manager_id;
        self.touch();
    }
    
    /// Put on leave
    pub fn start_leave(&mut self) -> Result<(), EmployeeError> {
        if self.status != EmploymentStatus::Active {
            return Err(EmployeeError::InvalidStateTransition);
        }
        self.status = EmploymentStatus::OnLeave;
        self.touch();
        Ok(())
    }
    
    /// Return from leave
    pub fn end_leave(&mut self) -> Result<(), EmployeeError> {
        if self.status != EmploymentStatus::OnLeave {
            return Err(EmployeeError::InvalidStateTransition);
        }
        self.status = EmploymentStatus::Active;
        self.touch();
        Ok(())
    }
    
    /// Terminate employment
    pub fn terminate(&mut self, termination_date: NaiveDate, reason: impl Into<String>) -> Result<(), EmployeeError> {
        if self.status == EmploymentStatus::Terminated {
            return Err(EmployeeError::AlreadyTerminated);
        }
        
        self.status = EmploymentStatus::Terminated;
        self.employment.termination_date = Some(termination_date);
        self.touch();
        
        self.raise_event(DomainEvent::Employee(EmployeeEvent::Terminated {
            employee_id: self.employee_id.clone(),
            termination_date,
            reason: reason.into(),
        }));
        
        Ok(())
    }
    
    /// Enroll in benefits
    pub fn enroll_in_benefit(&mut self, plan_id: impl Into<String>, coverage: CoverageLevel) {
        self.benefits_elections.push(BenefitElection {
            benefit_plan_id: plan_id.into(),
            coverage_level: coverage,
            dependents: vec![],
            enrolled_at: Utc::now(),
        });
        self.touch();
    }
    
    /// Add emergency contact
    pub fn add_emergency_contact(&mut self, contact: EmergencyContact) {
        self.emergency_contacts.push(contact);
        self.touch();
    }
    
    /// Calculate years of service
    pub fn years_of_service(&self) -> f64 {
        if let Some(hire_date) = self.employment.hire_date {
            let end_date = self.employment.termination_date
                .unwrap_or_else(|| chrono::Utc::now().date_naive());
            let days = (end_date - hire_date).num_days();
            days as f64 / 365.25
        } else {
            0.0
        }
    }
    
    pub fn take_events(&mut self) -> Vec<DomainEvent> {
        std::mem::take(&mut self.events)
    }
    
    fn raise_event(&mut self, event: DomainEvent) {
        self.events.push(event);
    }
    
    fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmployeeError {
    InvalidStateTransition,
    AlreadyTerminated,
    NotFound,
}

impl std::error::Error for EmployeeError {}
impl std::fmt::Display for EmployeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStateTransition => write!(f, "Invalid state transition"),
            Self::AlreadyTerminated => write!(f, "Employee already terminated"),
            Self::NotFound => write!(f, "Employee not found"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_employee() -> Employee {
        Employee::hire(
            EmployeeId::new(2024, 1),
            "John",
            "Doe",
            "john.doe@company.com",
            "Software Engineer",
            NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        )
    }
    
    #[test]
    fn test_employee_hire() {
        let emp = create_test_employee();
        assert_eq!(emp.full_name(), "John Doe");
        assert!(emp.is_active());
        assert_eq!(emp.employment().job_title, "Software Engineer");
    }
    
    #[test]
    fn test_employee_promotion() {
        let mut emp = create_test_employee();
        emp.promote("Senior Software Engineer", None);
        assert_eq!(emp.employment().job_title, "Senior Software Engineer");
    }
    
    #[test]
    fn test_leave_management() {
        let mut emp = create_test_employee();
        emp.start_leave().unwrap();
        assert_eq!(emp.status(), &EmploymentStatus::OnLeave);
        
        emp.end_leave().unwrap();
        assert!(emp.is_active());
    }
    
    #[test]
    fn test_termination() {
        let mut emp = create_test_employee();
        emp.terminate(NaiveDate::from_ymd_opt(2024, 12, 31).unwrap(), "Resignation").unwrap();
        assert_eq!(emp.status(), &EmploymentStatus::Terminated);
    }
}
