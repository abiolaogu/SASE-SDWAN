//! OpenSASE Scheduling Platform - DDD Implementation (Calendly replacement)
pub mod domain;
pub use domain::aggregates::{EventType, Booking, BookingError};
pub use domain::value_objects::{TimeSlot, Availability};
pub use domain::events::{DomainEvent, SchedulingEvent};
