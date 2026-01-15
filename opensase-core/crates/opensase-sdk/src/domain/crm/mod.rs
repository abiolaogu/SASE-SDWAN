//! CRM domain types
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::{Address, Metadata};

/// Contact entity
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Contact {
    pub id: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    pub email: String,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub account: Option<AccountRef>,
    #[serde(default)]
    pub owner: Option<OwnerRef>,
    #[serde(default)]
    pub lead_status: Option<String>,
    #[serde(default)]
    pub lead_score: Option<i32>,
    #[serde(default)]
    pub lifecycle_stage: Option<String>,
    #[serde(default)]
    pub address: Option<Address>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub custom_fields: Metadata,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountRef { pub id: String, pub name: String }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OwnerRef { pub id: String, pub name: String }

/// Create contact params
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateContactParams {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lead_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

impl CreateContactParams {
    pub fn builder() -> CreateContactParamsBuilder { CreateContactParamsBuilder::default() }
}

#[derive(Debug, Clone, Default)]
pub struct CreateContactParamsBuilder { params: CreateContactParams }

impl CreateContactParamsBuilder {
    pub fn email(mut self, e: impl Into<String>) -> Self { self.params.email = e.into(); self }
    pub fn first_name(mut self, n: impl Into<String>) -> Self { self.params.first_name = Some(n.into()); self }
    pub fn last_name(mut self, n: impl Into<String>) -> Self { self.params.last_name = Some(n.into()); self }
    pub fn build(self) -> CreateContactParams { self.params }
}
