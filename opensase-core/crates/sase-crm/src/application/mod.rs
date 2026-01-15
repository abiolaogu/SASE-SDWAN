//! Application layer
//!
//! Orchestrates use cases and coordinates domain objects.

pub mod commands;
pub mod queries;
pub mod dto;

pub use commands::{ContactService, DealService};
pub use dto::*;
