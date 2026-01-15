//! Domain events for HR bounded context

use chrono::NaiveDate;
use rust_decimal::Decimal;
use crate::domain::value_objects::EmployeeId;

/// All domain events
#[derive(Clone, Debug)]
pub enum DomainEvent {
    Employee(EmployeeEvent),
    Payroll(PayrollEvent),
    TimeTracking(TimeTrackingEvent),
}

#[derive(Clone, Debug)]
pub enum EmployeeEvent {
    Hired {
        employee_id: EmployeeId,
        hire_date: NaiveDate,
    },
    Promoted {
        employee_id: EmployeeId,
        old_title: String,
        new_title: String,
    },
    CompensationChanged {
        employee_id: EmployeeId,
        new_amount: Decimal,
        effective_date: NaiveDate,
    },
    Terminated {
        employee_id: EmployeeId,
        termination_date: NaiveDate,
        reason: String,
    },
    OnLeaveStarted {
        employee_id: EmployeeId,
        leave_type: String,
        start_date: NaiveDate,
    },
    OnLeaveEnded {
        employee_id: EmployeeId,
        return_date: NaiveDate,
    },
}

#[derive(Clone, Debug)]
pub enum PayrollEvent {
    Created {
        payroll_id: String,
        pay_period_start: NaiveDate,
        pay_period_end: NaiveDate,
    },
    Approved {
        payroll_id: String,
        employee_count: u32,
        total_amount: Decimal,
    },
    Completed {
        payroll_id: String,
        check_date: NaiveDate,
        total_disbursed: Decimal,
    },
    Failed {
        payroll_id: String,
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub enum TimeTrackingEvent {
    ClockedIn {
        employee_id: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    ClockedOut {
        employee_id: String,
        timestamp: chrono::DateTime<chrono::Utc>,
        hours_worked: Decimal,
    },
    TimeOffRequested {
        employee_id: String,
        start_date: NaiveDate,
        end_date: NaiveDate,
        leave_type: String,
    },
    TimeOffApproved {
        request_id: String,
        approved_by: String,
    },
}
