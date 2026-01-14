//! OpenSASE Domain Model
//!
//! # Domain-Driven Design Architecture
//!
//! This module implements DDD principles:
//! - **Bounded Contexts**: Policy, Path, DLP, Identity
//! - **Aggregates**: PolicyAggregate, SessionAggregate
//! - **Value Objects**: FlowId, PolicyId, Score
//! - **Domain Events**: PolicyApplied, PathSwitched, ViolationDetected
//! - **Repositories**: PolicyRepository, SessionRepository
//!
//! # Extreme Programming Practices
//! - TDD: All domain logic has comprehensive tests
//! - Simple Design: Single responsibility, minimal complexity
//! - Refactoring: Continuous improvement
//!
//! # Legacy Modernization
//! - Anti-Corruption Layer: Adapters for external systems
//! - Strangler Fig: Gradual replacement of Python components

pub mod value_objects;
pub mod aggregates;
pub mod events;
pub mod repositories;

pub use value_objects::*;
pub use aggregates::*;
pub use events::*;
