//! OpenSASE Support Platform - DDD Implementation (Zendesk replacement)
pub mod domain;
pub use domain::aggregates::{Ticket, Agent, TicketError};
pub use domain::value_objects::TicketId;
pub use domain::events::{DomainEvent, TicketEvent};
