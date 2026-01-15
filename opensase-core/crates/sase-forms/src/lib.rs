//! OpenSASE Form Builder Platform
//!
//! Self-hosted form builder replacing Typeform, JotForm, Google Forms.
//!
//! ## Features
//! - Drag-and-drop form builder
//! - Conditional logic
//! - File uploads
//! - Integrations and webhooks
//! - Analytics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Form {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub status: FormStatus,
    pub fields: Vec<FormField>,
    pub settings: FormSettings,
    pub theme: FormTheme,
    pub submission_count: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum FormStatus {
    #[default]
    Draft,
    Published,
    Closed,
    Archived,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormField {
    pub id: String,
    pub field_type: FieldType,
    pub label: String,
    pub description: Option<String>,
    pub placeholder: Option<String>,
    pub required: bool,
    pub validation: Option<FieldValidation>,
    pub options: Vec<FieldOption>,
    pub conditional: Option<FieldConditional>,
    pub order: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FieldType {
    ShortText,
    LongText,
    Email,
    Phone,
    Number,
    Date,
    Time,
    DateTime,
    SingleChoice,
    MultipleChoice,
    Dropdown,
    Rating,
    Scale,
    FileUpload,
    Signature,
    Address,
    Hidden,
    Section,
    PageBreak,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FieldValidation {
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub pattern: Option<String>,
    pub custom_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldOption {
    pub id: String,
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldConditional {
    pub source_field_id: String,
    pub operator: ConditionalOperator,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConditionalOperator {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
    IsEmpty,
    IsNotEmpty,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FormSettings {
    pub submit_button_text: String,
    pub success_message: String,
    pub redirect_url: Option<String>,
    pub notifications: Vec<NotificationSettings>,
    pub limit_responses: Option<u64>,
    pub close_date: Option<DateTime<Utc>>,
    pub require_login: bool,
    pub one_response_per_user: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub email: String,
    pub subject: String,
    pub include_responses: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FormTheme {
    pub primary_color: String,
    pub background_color: String,
    pub font_family: String,
    pub logo_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormSubmission {
    pub id: String,
    pub form_id: String,
    pub responses: HashMap<String, serde_json::Value>,
    pub metadata: SubmissionMetadata,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubmissionMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub referrer: Option<String>,
    pub duration_seconds: Option<u32>,
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum FormsError {
    #[error("Form not found")]
    FormNotFound,
    
    #[error("Field not found")]
    FieldNotFound,
    
    #[error("Submission not found")]
    SubmissionNotFound,
    
    #[error("Form closed")]
    FormClosed,
    
    #[error("Response limit reached")]
    ResponseLimitReached,
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, FormsError>;
