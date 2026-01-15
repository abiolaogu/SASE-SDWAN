//! Domain module
//!
//! Contains all domain logic following DDD principles.

pub mod aggregates;
pub mod value_objects;
pub mod events;
pub mod services;

pub use aggregates::*;
pub use value_objects::*;
pub use events::*;
