//! OpenSASE CRM Platform (OSCRM)
//!
//! Self-hosted CRM replacing Salesforce, HubSpot CRM, Pipedrive.
//!
//! ## Features
//! - Contact and account management with 360° view
//! - Sales pipeline with customizable stages
//! - Opportunity tracking and forecasting
//! - AI-powered lead scoring
//! - Activity tracking and workflow automation

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub mod contacts;
pub mod accounts;
pub mod deals;
pub mod pipeline;
pub mod activities;
pub mod forecast;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    pub account_id: Option<String>,
    pub owner_id: String,
    pub lead_source: Option<LeadSource>,
    pub lead_status: LeadStatus,
    pub lead_score: i32,
    pub lifecycle_stage: LifecycleStage,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, serde_json::Value>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeadStatus {
    #[default]
    New,
    Contacted,
    Qualified,
    Unqualified,
    Nurturing,
    Converted,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum LifecycleStage {
    Subscriber,
    #[default]
    Lead,
    MarketingQualifiedLead,
    SalesQualifiedLead,
    Opportunity,
    Customer,
    Evangelist,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LeadSource {
    Website,
    Referral,
    SocialMedia,
    Email,
    PaidAds,
    Event,
    Partner,
    Other(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub domain: Option<String>,
    pub industry: Option<String>,
    pub company_size: Option<CompanySize>,
    pub annual_revenue: Option<f64>,
    pub website: Option<String>,
    pub phone: Option<String>,
    pub owner_id: String,
    pub parent_account_id: Option<String>,
    pub account_type: AccountType,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum CompanySize {
    #[default]
    Unknown,
    Startup,
    SmallBusiness,
    MidMarket,
    Enterprise,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum AccountType {
    #[default]
    Prospect,
    Customer,
    Partner,
    Vendor,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deal {
    pub id: String,
    pub name: String,
    pub amount: f64,
    pub currency: String,
    pub pipeline_id: String,
    pub stage_id: String,
    pub probability: f32,
    pub expected_close_date: Option<NaiveDate>,
    pub actual_close_date: Option<NaiveDate>,
    pub contact_id: Option<String>,
    pub account_id: Option<String>,
    pub owner_id: String,
    pub deal_type: DealType,
    pub status: DealStatus,
    pub lost_reason: Option<String>,
    pub next_step: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum DealStatus {
    #[default]
    Open,
    Won,
    Lost,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum DealType {
    #[default]
    NewBusiness,
    Renewal,
    Upsell,
    CrossSell,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pipeline {
    pub id: String,
    pub name: String,
    pub stages: Vec<PipelineStage>,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineStage {
    pub id: String,
    pub name: String,
    pub probability: f32,
    pub order: u32,
    pub rotting_days: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Activity {
    pub id: String,
    pub activity_type: ActivityType,
    pub contact_id: Option<String>,
    pub account_id: Option<String>,
    pub deal_id: Option<String>,
    pub user_id: String,
    pub subject: String,
    pub description: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActivityType {
    Call,
    Email,
    Meeting,
    Task,
    Note,
    Demo,
    Proposal,
    Other(String),
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum CrmError {
    #[error("Contact not found")]
    ContactNotFound,
    
    #[error("Account not found")]
    AccountNotFound,
    
    #[error("Deal not found")]
    DealNotFound,
    
    #[error("Pipeline not found")]
    PipelineNotFound,
    
    #[error("Stage not found")]
    StageNotFound,
    
    #[error("Duplicate contact: {0}")]
    DuplicateContact(String),
    
    #[error("Stage requirement not met: {0}")]
    StageRequirementNotMet(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, CrmError>;
