//! Ports module (Hexagonal Architecture)
//!
//! Defines interfaces for external dependencies.

pub mod inbound;
pub mod outbound;

pub use inbound::*;
pub use outbound::*;
