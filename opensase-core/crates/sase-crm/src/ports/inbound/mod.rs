//! Inbound ports (Use case traits)
//!
//! Hexagonal architecture: application service interfaces.

use async_trait::async_trait;
use crate::domain::aggregates::{Contact, Deal};
use crate::domain::value_objects::{EntityId, Email};
use crate::application::dto::*;

/// Contact management use cases
#[async_trait]
pub trait ContactUseCases: Send + Sync {
    /// Create a new contact
    async fn create_contact(&self, command: CreateContactCommand) -> Result<Contact, UseCaseError>;
    
    /// Update contact information
    async fn update_contact(&self, command: UpdateContactCommand) -> Result<Contact, UseCaseError>;
    
    /// Qualify a lead
    async fn qualify_contact(&self, contact_id: &EntityId) -> Result<Contact, UseCaseError>;
    
    /// Convert contact to customer
    async fn convert_to_customer(&self, contact_id: &EntityId) -> Result<Contact, UseCaseError>;
    
    /// Get contact by ID
    async fn get_contact(&self, id: &EntityId) -> Result<Option<Contact>, UseCaseError>;
    
    /// Get contact 360 view
    async fn get_contact_360(&self, id: &EntityId) -> Result<Contact360View, UseCaseError>;
    
    /// Search contacts
    async fn search_contacts(&self, query: &str, limit: usize) -> Result<Vec<Contact>, UseCaseError>;
    
    /// Merge contacts
    async fn merge_contacts(&self, primary_id: &EntityId, secondary_id: &EntityId) -> Result<Contact, UseCaseError>;
}

/// Deal management use cases
#[async_trait]
pub trait DealUseCases: Send + Sync {
    /// Create a new deal
    async fn create_deal(&self, command: CreateDealCommand) -> Result<Deal, UseCaseError>;
    
    /// Move deal to stage
    async fn move_to_stage(&self, deal_id: &EntityId, stage_id: &EntityId, probability: u8) -> Result<Deal, UseCaseError>;
    
    /// Close deal as won
    async fn close_won(&self, deal_id: &EntityId) -> Result<Deal, UseCaseError>;
    
    /// Close deal as lost
    async fn close_lost(&self, deal_id: &EntityId, reason: String) -> Result<Deal, UseCaseError>;
    
    /// Get pipeline view
    async fn get_pipeline_view(&self, pipeline_id: &EntityId) -> Result<PipelineView, UseCaseError>;
    
    /// Get forecast
    async fn get_forecast(&self, owner_id: Option<&EntityId>) -> Result<ForecastView, UseCaseError>;
}

#[derive(Debug, Clone)]
pub enum UseCaseError {
    NotFound(String),
    ValidationError(String),
    DomainError(String),
    RepositoryError(String),
    Unauthorized,
}

impl std::error::Error for UseCaseError {}

impl std::fmt::Display for UseCaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(e) => write!(f, "Not found: {}", e),
            Self::ValidationError(e) => write!(f, "Validation error: {}", e),
            Self::DomainError(e) => write!(f, "Domain error: {}", e),
            Self::RepositoryError(e) => write!(f, "Repository error: {}", e),
            Self::Unauthorized => write!(f, "Unauthorized"),
        }
    }
}
