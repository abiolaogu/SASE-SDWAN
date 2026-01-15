//! OpenSASE Payments Platform - DDD Implementation
//!
//! Self-hosted payment gateway, Stripe alternative.

pub mod domain;

pub use domain::aggregates::{Payment, Subscription, PaymentError, SubscriptionError};
pub use domain::value_objects::{PaymentId, PaymentMethod};
pub use domain::events::{DomainEvent, PaymentEvent, SubscriptionEvent};
