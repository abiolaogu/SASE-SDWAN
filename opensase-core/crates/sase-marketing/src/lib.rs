//! OpenSASE Marketing Automation Platform
//!
//! Self-hosted marketing replacing HubSpot, Mailchimp, Marketo.
//!
//! ## Features
//! - Email campaigns and automation
//! - Contact segmentation
//! - Landing pages
//! - Analytics and reporting
//! - A/B testing

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub campaign_type: CampaignType,
    pub status: CampaignStatus,
    pub subject: Option<String>,
    pub from_name: String,
    pub from_email: String,
    pub reply_to: Option<String>,
    pub content_html: Option<String>,
    pub content_text: Option<String>,
    pub list_ids: Vec<String>,
    pub segment_ids: Vec<String>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub sent_at: Option<DateTime<Utc>>,
    pub stats: CampaignStats,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum CampaignType {
    #[default]
    Email,
    Sms,
    Push,
    InApp,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum CampaignStatus {
    #[default]
    Draft,
    Scheduled,
    Sending,
    Sent,
    Paused,
    Cancelled,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CampaignStats {
    pub sent: u64,
    pub delivered: u64,
    pub opened: u64,
    pub clicked: u64,
    pub bounced: u64,
    pub unsubscribed: u64,
    pub complaints: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactList {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub contact_count: u64,
    pub is_dynamic: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Segment {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub conditions: Vec<SegmentCondition>,
    pub contact_count: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SegmentCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    IsSet,
    IsNotSet,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Automation {
    pub id: String,
    pub name: String,
    pub trigger: AutomationTrigger,
    pub steps: Vec<AutomationStep>,
    pub status: AutomationStatus,
    pub enrolled_count: u64,
    pub completed_count: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AutomationTrigger {
    ContactCreated,
    FormSubmission { form_id: String },
    TagAdded { tag: String },
    ListJoined { list_id: String },
    DateBased { field: String, offset_days: i32 },
    Custom { event: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutomationStep {
    pub id: String,
    pub step_type: StepType,
    pub delay_minutes: Option<u32>,
    pub conditions: Vec<SegmentCondition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StepType {
    SendEmail { template_id: String },
    SendSms { message: String },
    AddTag { tag: String },
    RemoveTag { tag: String },
    AddToList { list_id: String },
    RemoveFromList { list_id: String },
    Webhook { url: String },
    Wait { minutes: u32 },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum AutomationStatus {
    #[default]
    Draft,
    Active,
    Paused,
    Archived,
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum MarketingError {
    #[error("Campaign not found")]
    CampaignNotFound,
    
    #[error("List not found")]
    ListNotFound,
    
    #[error("Template not found")]
    TemplateNotFound,
    
    #[error("Invalid email")]
    InvalidEmail,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, MarketingError>;
