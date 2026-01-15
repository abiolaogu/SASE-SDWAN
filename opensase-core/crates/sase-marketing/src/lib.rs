//! OpenSASE Marketing Platform - DDD Implementation (HubSpot replacement)
pub mod domain;
pub use domain::aggregates::{Campaign, Automation, CampaignError};
pub use domain::events::{DomainEvent, CampaignEvent};
