//! OpenSASE CRM Platform (OSCRM)
//!
//! Enterprise-grade CRM platform following Domain-Driven Design (DDD),
//! Extreme Programming (XP), and Legacy Modernization principles.
//!
//! ## Architecture
//!
//! - **Domain Layer**: Rich aggregates, value objects, domain events
//! - **Application Layer**: Use case orchestration, DTOs
//! - **Ports Layer**: Hexagonal architecture interfaces
//! - **Infrastructure Layer**: Concrete implementations
//!
//! ## Key Aggregates
//!
//! - **Contact**: Lead/contact management with lifecycle stages
//! - **Deal**: Sales opportunity with pipeline stages
//! - **Account**: Company/organization management
//!
//! ## Features
//!
//! - Contact and account management with 360° view
//! - Sales pipeline with customizable stages
//! - Opportunity tracking and forecasting
//! - AI-powered lead scoring
//! - Domain events for integration

pub mod domain;
pub mod application;
pub mod ports;
pub mod infrastructure;

// Re-exports for convenience
pub use domain::aggregates::{Contact, Deal, LeadStatus, LifecycleStage, DealStatus};
pub use domain::value_objects::{Email, Money, Currency, Phone, Address, EntityId};
pub use domain::events::{DomainEvent, ContactEvent, DealEvent};
pub use application::{ContactService, DealService};
pub use ports::inbound::{ContactUseCases, DealUseCases, UseCaseError};
pub use ports::outbound::{ContactRepository, DealRepository, RepositoryError};

// Legacy module stubs (removed, now using DDD structure)
pub mod contacts { pub use crate::domain::aggregates::contact::*; }
pub mod accounts { pub use crate::domain::aggregates::*; }
pub mod deals { pub use crate::domain::aggregates::deal::*; }
pub mod pipeline { pub use crate::domain::aggregates::*; }
pub mod activities { pub struct ActivityTracker; }
pub mod forecast { pub use crate::domain::services::ForecastService; }
