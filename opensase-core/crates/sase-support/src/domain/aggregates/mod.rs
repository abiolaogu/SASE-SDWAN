//! Aggregates
pub mod ticket;
pub mod agent;
pub use ticket::{Ticket, TicketError, TicketStatus, Comment};
pub use agent::{Agent, AgentRole, AgentStatus};
