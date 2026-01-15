//! Command handlers
//!
//! Application services that orchestrate use cases.

use std::sync::Arc;
use async_trait::async_trait;

use crate::domain::aggregates::{Contact, Deal};
use crate::domain::value_objects::{Email, EntityId, Money, Currency};
use crate::domain::services::LeadScoringService;
use crate::ports::outbound::{ContactRepository, DealRepository, EventPublisher, RepositoryError};
use crate::ports::inbound::{ContactUseCases, DealUseCases, UseCaseError};
use crate::application::dto::*;

/// Contact application service
pub struct ContactService {
    contact_repo: Arc<dyn ContactRepository>,
    event_publisher: Arc<dyn EventPublisher>,
}

impl ContactService {
    pub fn new(
        contact_repo: Arc<dyn ContactRepository>,
        event_publisher: Arc<dyn EventPublisher>,
    ) -> Self {
        Self {
            contact_repo,
            event_publisher,
        }
    }
}

#[async_trait]
impl ContactUseCases for ContactService {
    async fn create_contact(&self, command: CreateContactCommand) -> Result<Contact, UseCaseError> {
        // Validate email
        let email = Email::new(&command.email)
            .map_err(|e| UseCaseError::ValidationError(e.to_string()))?;
        
        // Check for duplicates
        if let Some(_existing) = self.contact_repo.find_by_email(&email).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))? 
        {
            return Err(UseCaseError::ValidationError("Contact with this email already exists".into()));
        }
        
        // Create contact aggregate
        let owner_id = EntityId::from_string(&command.owner_id);
        let mut contact = Contact::create(email, command.first_name, command.last_name, owner_id);
        
        // Add optional data
        if let Some(tags) = command.tags {
            for tag in tags {
                contact.add_tag(tag);
            }
        }
        
        // Calculate initial lead score
        let score = LeadScoringService::calculate_score(&contact, 0, 0, 0);
        contact.update_lead_score(score);
        
        // Persist
        self.contact_repo.save(&contact).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        // Publish events
        let events = contact.take_events();
        self.event_publisher.publish(events).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(contact)
    }
    
    async fn update_contact(&self, command: UpdateContactCommand) -> Result<Contact, UseCaseError> {
        let id = EntityId::from_string(&command.contact_id);
        
        let mut contact = self.contact_repo.find_by_id(&id).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?
            .ok_or_else(|| UseCaseError::NotFound("Contact not found".into()))?;
        
        contact.update_info(
            command.first_name,
            command.last_name,
            command.title,
            command.department,
        );
        
        self.contact_repo.save(&contact).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(contact)
    }
    
    async fn qualify_contact(&self, contact_id: &EntityId) -> Result<Contact, UseCaseError> {
        let mut contact = self.contact_repo.find_by_id(contact_id).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?
            .ok_or_else(|| UseCaseError::NotFound("Contact not found".into()))?;
        
        contact.qualify()
            .map_err(|e| UseCaseError::DomainError(e.to_string()))?;
        
        self.contact_repo.save(&contact).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        // Publish events
        let events = contact.take_events();
        self.event_publisher.publish(events).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(contact)
    }
    
    async fn convert_to_customer(&self, contact_id: &EntityId) -> Result<Contact, UseCaseError> {
        let mut contact = self.contact_repo.find_by_id(contact_id).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?
            .ok_or_else(|| UseCaseError::NotFound("Contact not found".into()))?;
        
        contact.convert_to_customer()
            .map_err(|e| UseCaseError::DomainError(e.to_string()))?;
        
        self.contact_repo.save(&contact).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        let events = contact.take_events();
        self.event_publisher.publish(events).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(contact)
    }
    
    async fn get_contact(&self, id: &EntityId) -> Result<Option<Contact>, UseCaseError> {
        self.contact_repo.find_by_id(id).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))
    }
    
    async fn get_contact_360(&self, _id: &EntityId) -> Result<Contact360View, UseCaseError> {
        // This would aggregate data from multiple sources
        Err(UseCaseError::NotFound("Not implemented".into()))
    }
    
    async fn search_contacts(&self, query: &str, limit: usize) -> Result<Vec<Contact>, UseCaseError> {
        self.contact_repo.search(query, limit).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))
    }
    
    async fn merge_contacts(&self, _primary_id: &EntityId, _secondary_id: &EntityId) -> Result<Contact, UseCaseError> {
        Err(UseCaseError::NotFound("Not implemented".into()))
    }
}

/// Deal application service
pub struct DealService {
    deal_repo: Arc<dyn DealRepository>,
    event_publisher: Arc<dyn EventPublisher>,
}

impl DealService {
    pub fn new(
        deal_repo: Arc<dyn DealRepository>,
        event_publisher: Arc<dyn EventPublisher>,
    ) -> Self {
        Self {
            deal_repo,
            event_publisher,
        }
    }
}

#[async_trait]
impl DealUseCases for DealService {
    async fn create_deal(&self, command: CreateDealCommand) -> Result<Deal, UseCaseError> {
        let amount = Money::new(
            command.amount,
            Currency::from_code(&command.currency),
        );
        
        let pipeline_id = EntityId::from_string(&command.pipeline_id);
        let owner_id = EntityId::from_string(&command.owner_id);
        let initial_stage = EntityId::new(); // Would come from pipeline service
        
        let mut deal = Deal::create(
            command.name,
            amount,
            pipeline_id,
            initial_stage,
            owner_id,
        );
        
        if let Some(date) = command.expected_close_date {
            deal.set_expected_close_date(date);
        }
        
        if let Some(contact_id) = command.contact_id {
            deal.link_contact(EntityId::from_string(&contact_id));
        }
        
        if let Some(account_id) = command.account_id {
            deal.link_account(EntityId::from_string(&account_id));
        }
        
        self.deal_repo.save(&deal).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        let events = deal.take_events();
        self.event_publisher.publish(events).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(deal)
    }
    
    async fn move_to_stage(&self, deal_id: &EntityId, stage_id: &EntityId, probability: u8) -> Result<Deal, UseCaseError> {
        let mut deal = self.deal_repo.find_by_id(deal_id).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?
            .ok_or_else(|| UseCaseError::NotFound("Deal not found".into()))?;
        
        deal.move_to_stage(stage_id.clone(), probability)
            .map_err(|e| UseCaseError::DomainError(e.to_string()))?;
        
        self.deal_repo.save(&deal).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        let events = deal.take_events();
        self.event_publisher.publish(events).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(deal)
    }
    
    async fn close_won(&self, deal_id: &EntityId) -> Result<Deal, UseCaseError> {
        let mut deal = self.deal_repo.find_by_id(deal_id).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?
            .ok_or_else(|| UseCaseError::NotFound("Deal not found".into()))?;
        
        deal.close_won()
            .map_err(|e| UseCaseError::DomainError(e.to_string()))?;
        
        self.deal_repo.save(&deal).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        let events = deal.take_events();
        self.event_publisher.publish(events).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(deal)
    }
    
    async fn close_lost(&self, deal_id: &EntityId, reason: String) -> Result<Deal, UseCaseError> {
        let mut deal = self.deal_repo.find_by_id(deal_id).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?
            .ok_or_else(|| UseCaseError::NotFound("Deal not found".into()))?;
        
        deal.close_lost(reason)
            .map_err(|e| UseCaseError::DomainError(e.to_string()))?;
        
        self.deal_repo.save(&deal).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        let events = deal.take_events();
        self.event_publisher.publish(events).await
            .map_err(|e| UseCaseError::RepositoryError(e.to_string()))?;
        
        Ok(deal)
    }
    
    async fn get_pipeline_view(&self, _pipeline_id: &EntityId) -> Result<PipelineView, UseCaseError> {
        Err(UseCaseError::NotFound("Not implemented".into()))
    }
    
    async fn get_forecast(&self, _owner_id: Option<&EntityId>) -> Result<ForecastView, UseCaseError> {
        Err(UseCaseError::NotFound("Not implemented".into()))
    }
}
