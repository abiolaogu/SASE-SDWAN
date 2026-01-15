//! In-memory repository implementations for testing

use std::collections::HashMap;
use std::sync::RwLock;
use async_trait::async_trait;

use crate::domain::aggregates::{Contact, Deal};
use crate::domain::value_objects::{Email, EntityId};
use crate::domain::DomainEvent;
use crate::ports::outbound::{ContactRepository, DealRepository, EventPublisher, RepositoryError};

/// In-memory contact repository (for testing)
#[derive(Default)]
pub struct InMemoryContactRepository {
    contacts: RwLock<HashMap<String, Contact>>,
}

impl InMemoryContactRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ContactRepository for InMemoryContactRepository {
    async fn find_by_id(&self, id: &EntityId) -> Result<Option<Contact>, RepositoryError> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.get(id.as_str()).cloned())
    }
    
    async fn find_by_email(&self, email: &Email) -> Result<Option<Contact>, RepositoryError> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.values().find(|c| c.email() == email).cloned())
    }
    
    async fn find_by_account(&self, account_id: &EntityId) -> Result<Vec<Contact>, RepositoryError> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.values()
            .filter(|c| c.account_id().map(|a| a == account_id).unwrap_or(false))
            .cloned()
            .collect())
    }
    
    async fn find_by_owner(&self, owner_id: &EntityId) -> Result<Vec<Contact>, RepositoryError> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.values()
            .filter(|c| c.owner_id() == owner_id)
            .cloned()
            .collect())
    }
    
    async fn save(&self, contact: &Contact) -> Result<(), RepositoryError> {
        let mut contacts = self.contacts.write().unwrap();
        contacts.insert(contact.id().to_string(), contact.clone());
        Ok(())
    }
    
    async fn delete(&self, id: &EntityId) -> Result<(), RepositoryError> {
        let mut contacts = self.contacts.write().unwrap();
        contacts.remove(id.as_str());
        Ok(())
    }
    
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Contact>, RepositoryError> {
        let contacts = self.contacts.read().unwrap();
        let query = query.to_lowercase();
        Ok(contacts.values()
            .filter(|c| {
                c.first_name().to_lowercase().contains(&query) ||
                c.last_name().to_lowercase().contains(&query) ||
                c.email().as_str().contains(&query)
            })
            .take(limit)
            .cloned()
            .collect())
    }
    
    async fn count_by_owner(&self, owner_id: &EntityId) -> Result<u64, RepositoryError> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.values()
            .filter(|c| c.owner_id() == owner_id)
            .count() as u64)
    }
}

/// In-memory deal repository (for testing)
#[derive(Default)]
pub struct InMemoryDealRepository {
    deals: RwLock<HashMap<String, Deal>>,
}

impl InMemoryDealRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DealRepository for InMemoryDealRepository {
    async fn find_by_id(&self, id: &EntityId) -> Result<Option<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.get(id.as_str()).cloned())
    }
    
    async fn find_by_pipeline(&self, pipeline_id: &EntityId) -> Result<Vec<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.values()
            .filter(|d| d.pipeline_id() == pipeline_id)
            .cloned()
            .collect())
    }
    
    async fn find_by_stage(&self, stage_id: &EntityId) -> Result<Vec<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.values()
            .filter(|d| d.stage_id() == stage_id)
            .cloned()
            .collect())
    }
    
    async fn find_by_owner(&self, owner_id: &EntityId) -> Result<Vec<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.values()
            .filter(|d| d.owner_id() == owner_id)
            .cloned()
            .collect())
    }
    
    async fn find_by_contact(&self, contact_id: &EntityId) -> Result<Vec<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.values()
            .filter(|d| d.contact_id().map(|c| c == contact_id).unwrap_or(false))
            .cloned()
            .collect())
    }
    
    async fn find_by_account(&self, account_id: &EntityId) -> Result<Vec<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.values()
            .filter(|d| d.account_id().map(|a| a == account_id).unwrap_or(false))
            .cloned()
            .collect())
    }
    
    async fn find_open(&self) -> Result<Vec<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.values()
            .filter(|d| d.is_open())
            .cloned()
            .collect())
    }
    
    async fn find_closing_in_range(
        &self,
        start: chrono::NaiveDate,
        end: chrono::NaiveDate,
    ) -> Result<Vec<Deal>, RepositoryError> {
        let deals = self.deals.read().unwrap();
        Ok(deals.values()
            .filter(|d| {
                d.expected_close_date()
                    .map(|date| date >= start && date <= end)
                    .unwrap_or(false)
            })
            .cloned()
            .collect())
    }
    
    async fn save(&self, deal: &Deal) -> Result<(), RepositoryError> {
        let mut deals = self.deals.write().unwrap();
        deals.insert(deal.id().to_string(), deal.clone());
        Ok(())
    }
    
    async fn delete(&self, id: &EntityId) -> Result<(), RepositoryError> {
        let mut deals = self.deals.write().unwrap();
        deals.remove(id.as_str());
        Ok(())
    }
}

/// No-op event publisher for testing
#[derive(Default)]
pub struct NoOpEventPublisher;

#[async_trait]
impl EventPublisher for NoOpEventPublisher {
    async fn publish(&self, _events: Vec<DomainEvent>) -> Result<(), RepositoryError> {
        // No-op for testing
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::Money;
    use rust_decimal::Decimal;
    
    #[tokio::test]
    async fn test_contact_repository_save_and_find() {
        let repo = InMemoryContactRepository::new();
        
        let email = Email::new("test@example.com").unwrap();
        let contact = Contact::create(email.clone(), "John", "Doe", EntityId::new());
        
        repo.save(&contact).await.unwrap();
        
        let found = repo.find_by_id(contact.id()).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().email(), &email);
    }
    
    #[tokio::test]
    async fn test_contact_search() {
        let repo = InMemoryContactRepository::new();
        
        let email = Email::new("john@example.com").unwrap();
        let contact = Contact::create(email, "John", "Doe", EntityId::new());
        repo.save(&contact).await.unwrap();
        
        let results = repo.search("john", 10).await.unwrap();
        assert_eq!(results.len(), 1);
    }
    
    #[tokio::test]
    async fn test_deal_repository_save_and_find() {
        let repo = InMemoryDealRepository::new();
        
        let deal = Deal::create(
            "Test Deal",
            Money::usd(Decimal::new(100000, 0)),
            EntityId::new(),
            EntityId::new(),
            EntityId::new(),
        );
        
        repo.save(&deal).await.unwrap();
        
        let found = repo.find_by_id(deal.id()).await.unwrap();
        assert!(found.is_some());
    }
}
