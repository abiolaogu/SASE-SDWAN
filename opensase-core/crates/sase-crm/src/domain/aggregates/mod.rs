//! Aggregates module

pub mod contact;
pub mod deal;

pub use contact::{Contact, ContactError, LeadStatus, LifecycleStage, LeadScore};
pub use deal::{Deal, DealError, DealStatus, DealType, Probability, DealProduct, Competitor};
