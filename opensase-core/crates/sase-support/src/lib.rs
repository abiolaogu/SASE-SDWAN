//! OpenSASE Customer Support Platform
//!
//! Self-hosted support platform replacing Zendesk, Intercom, Freshdesk.
//!
//! ## Features
//! - Multi-channel ticket management
//! - SLA tracking and escalation
//! - Knowledge base
//! - Customer satisfaction surveys
//! - Agent performance metrics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub id: String,
    pub number: u64,
    pub subject: String,
    pub description: String,
    pub status: TicketStatus,
    pub priority: TicketPriority,
    pub channel: Channel,
    pub requester_id: String,
    pub assignee_id: Option<String>,
    pub group_id: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, serde_json::Value>,
    pub sla_policy_id: Option<String>,
    pub first_response_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub satisfaction_rating: Option<SatisfactionRating>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum TicketStatus {
    #[default]
    New,
    Open,
    Pending,
    OnHold,
    Solved,
    Closed,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TicketPriority {
    Low,
    #[default]
    Normal,
    High,
    Urgent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Channel {
    Email,
    Web,
    Chat,
    Phone,
    Social,
    Api,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SatisfactionRating {
    pub score: i32,
    pub comment: Option<String>,
    pub rated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: AgentRole,
    pub groups: Vec<String>,
    pub skills: Vec<String>,
    pub max_tickets: u32,
    pub is_available: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum AgentRole {
    #[default]
    Agent,
    Supervisor,
    Admin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlaPolicy {
    pub id: String,
    pub name: String,
    pub first_response_time_minutes: u32,
    pub resolution_time_minutes: u32,
    pub priority_multipliers: HashMap<String, f32>,
    pub business_hours_only: bool,
    pub is_active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnowledgeArticle {
    pub id: String,
    pub title: String,
    pub body: String,
    pub category_id: String,
    pub author_id: String,
    pub status: ArticleStatus,
    pub view_count: u64,
    pub helpful_count: u64,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum ArticleStatus {
    #[default]
    Draft,
    Published,
    Archived,
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum SupportError {
    #[error("Ticket not found")]
    TicketNotFound,
    
    #[error("Agent not found")]
    AgentNotFound,
    
    #[error("Article not found")]
    ArticleNotFound,
    
    #[error("SLA breach")]
    SlaBreach,
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, SupportError>;
