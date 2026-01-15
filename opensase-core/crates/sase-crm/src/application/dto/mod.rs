//! Data Transfer Objects (DTOs)
//!
//! Objects for transferring data across boundaries.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use crate::domain::value_objects::EntityId;

// =============================================================================
// Contact Commands
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateContactCommand {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    pub account_id: Option<String>,
    pub owner_id: String,
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateContactCommand {
    pub contact_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
}

// =============================================================================
// Deal Commands
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateDealCommand {
    pub name: String,
    pub amount: Decimal,
    pub currency: String,
    pub pipeline_id: String,
    pub contact_id: Option<String>,
    pub account_id: Option<String>,
    pub owner_id: String,
    pub expected_close_date: Option<NaiveDate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveDealStageCommand {
    pub deal_id: String,
    pub stage_id: String,
    pub probability: u8,
}

// =============================================================================
// Views (Read Models)
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact360View {
    pub contact: ContactView,
    pub account: Option<AccountView>,
    pub deals: Vec<DealSummary>,
    pub activities: Vec<ActivityView>,
    pub engagement_score: u8,
    pub next_steps: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactView {
    pub id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub full_name: String,
    pub phone: Option<String>,
    pub title: Option<String>,
    pub lead_status: String,
    pub lead_score: u8,
    pub lifecycle_stage: String,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountView {
    pub id: String,
    pub name: String,
    pub domain: Option<String>,
    pub industry: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DealSummary {
    pub id: String,
    pub name: String,
    pub amount: Decimal,
    pub currency: String,
    pub stage: String,
    pub probability: u8,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivityView {
    pub id: String,
    pub activity_type: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineView {
    pub pipeline_id: String,
    pub pipeline_name: String,
    pub stages: Vec<StageView>,
    pub total_deals: u32,
    pub total_value: Decimal,
    pub weighted_value: Decimal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StageView {
    pub id: String,
    pub name: String,
    pub order: u32,
    pub deals: Vec<DealSummary>,
    pub deal_count: u32,
    pub stage_value: Decimal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForecastView {
    pub period: String,
    pub quota: Option<Decimal>,
    pub closed_won: Decimal,
    pub committed: Decimal,
    pub best_case: Decimal,
    pub pipeline: Decimal,
    pub gap_to_quota: Option<Decimal>,
    pub at_risk_deals: Vec<DealSummary>,
}
