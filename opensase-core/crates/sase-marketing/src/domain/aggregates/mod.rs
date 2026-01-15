//! Aggregates
pub mod campaign;
pub mod automation;
pub use campaign::{Campaign, CampaignError, CampaignStatus, CampaignStats};
pub use automation::{Automation, AutomationStatus, AutomationTrigger, AutomationStep, StepType};
