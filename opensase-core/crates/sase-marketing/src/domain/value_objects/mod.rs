//! Marketing value objects
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum CampaignType { #[default] Email, Sms, Push, InApp, Social }

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Segment {
    pub id: String,
    pub name: String,
    pub filter: SegmentFilter,
    pub contact_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SegmentFilter {
    pub conditions: Vec<FilterCondition>,
    pub logic: FilterLogic,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum FilterLogic { #[default] And, Or }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}
