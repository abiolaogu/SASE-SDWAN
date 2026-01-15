//! Outbound ports (Repository traits)
//!
//! Hexagonal architecture: these are the interfaces that infrastructure must implement.

use async_trait::async_trait;
use crate::domain::aggregates::{Contact, Deal};
use crate::domain::value_objects::{EntityId, Email};

/// Contact repository port
#[async_trait]
pub trait ContactRepository: Send + Sync {
    /// Find contact by ID
    async fn find_by_id(&self, id: &EntityId) -> Result<Option<Contact>, RepositoryError>;
    
    /// Find contact by email
    async fn find_by_email(&self, email: &Email) -> Result<Option<Contact>, RepositoryError>;
    
    /// Find contacts by account
    async fn find_by_account(&self, account_id: &EntityId) -> Result<Vec<Contact>, RepositoryError>;
    
    /// Find contacts by owner
    async fn find_by_owner(&self, owner_id: &EntityId) -> Result<Vec<Contact>, RepositoryError>;
    
    /// Save contact (insert or update)
    async fn save(&self, contact: &Contact) -> Result<(), RepositoryError>;
    
    /// Delete contact
    async fn delete(&self, id: &EntityId) -> Result<(), RepositoryError>;
    
    /// Search contacts
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Contact>, RepositoryError>;
    
    /// Count contacts by owner
    async fn count_by_owner(&self, owner_id: &EntityId) -> Result<u64, RepositoryError>;
}

/// Deal repository port
#[async_trait]
pub trait DealRepository: Send + Sync {
    /// Find deal by ID
    async fn find_by_id(&self, id: &EntityId) -> Result<Option<Deal>, RepositoryError>;
    
    /// Find deals by pipeline
    async fn find_by_pipeline(&self, pipeline_id: &EntityId) -> Result<Vec<Deal>, RepositoryError>;
    
    /// Find deals by stage
    async fn find_by_stage(&self, stage_id: &EntityId) -> Result<Vec<Deal>, RepositoryError>;
    
    /// Find deals by owner
    async fn find_by_owner(&self, owner_id: &EntityId) -> Result<Vec<Deal>, RepositoryError>;
    
    /// Find deals by contact
    async fn find_by_contact(&self, contact_id: &EntityId) -> Result<Vec<Deal>, RepositoryError>;
    
    /// Find deals by account
    async fn find_by_account(&self, account_id: &EntityId) -> Result<Vec<Deal>, RepositoryError>;
    
    /// Find open deals
    async fn find_open(&self) -> Result<Vec<Deal>, RepositoryError>;
    
    /// Find deals closing in date range
    async fn find_closing_in_range(
        &self,
        start: chrono::NaiveDate,
        end: chrono::NaiveDate,
    ) -> Result<Vec<Deal>, RepositoryError>;
    
    /// Save deal
    async fn save(&self, deal: &Deal) -> Result<(), RepositoryError>;
    
    /// Delete deal
    async fn delete(&self, id: &EntityId) -> Result<(), RepositoryError>;
}

/// Event publisher port
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish domain events
    async fn publish(&self, events: Vec<crate::domain::DomainEvent>) -> Result<(), RepositoryError>;
}

/// Repository error type
#[derive(Debug, Clone)]
pub enum RepositoryError {
    NotFound,
    DuplicateKey(String),
    ConnectionError(String),
    QueryError(String),
    SerializationError(String),
}

impl std::error::Error for RepositoryError {}

impl std::fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Entity not found"),
            Self::DuplicateKey(k) => write!(f, "Duplicate key: {}", k),
            Self::ConnectionError(e) => write!(f, "Connection error: {}", e),
            Self::QueryError(e) => write!(f, "Query error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}
