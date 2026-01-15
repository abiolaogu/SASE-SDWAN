//! Contact Aggregate
//!
//! Rich aggregate root for contact management with encapsulated business logic.

use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::domain::value_objects::{Email, Phone, Address, EntityId};
use crate::domain::events::{DomainEvent, ContactEvent};

/// Contact aggregate root
#[derive(Clone, Debug)]
pub struct Contact {
    id: EntityId,
    email: Email,
    first_name: String,
    last_name: String,
    phone: Option<Phone>,
    mobile: Option<Phone>,
    title: Option<String>,
    department: Option<String>,
    address: Option<Address>,
    account_id: Option<EntityId>,
    owner_id: EntityId,
    lead_status: LeadStatus,
    lead_score: LeadScore,
    lifecycle_stage: LifecycleStage,
    tags: Vec<String>,
    custom_fields: HashMap<String, serde_json::Value>,
    last_activity_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    // Domain events accumulated during operations
    events: Vec<DomainEvent>,
}

impl Contact {
    /// Create a new contact (factory method)
    pub fn create(
        email: Email,
        first_name: impl Into<String>,
        last_name: impl Into<String>,
        owner_id: EntityId,
    ) -> Self {
        let now = Utc::now();
        let id = EntityId::new();
        
        let mut contact = Self {
            id: id.clone(),
            email: email.clone(),
            first_name: first_name.into(),
            last_name: last_name.into(),
            phone: None,
            mobile: None,
            title: None,
            department: None,
            address: None,
            account_id: None,
            owner_id: owner_id.clone(),
            lead_status: LeadStatus::New,
            lead_score: LeadScore::new(0),
            lifecycle_stage: LifecycleStage::Lead,
            tags: vec![],
            custom_fields: HashMap::new(),
            last_activity_at: None,
            created_at: now,
            updated_at: now,
            events: vec![],
        };
        
        // Raise domain event
        contact.raise_event(DomainEvent::Contact(ContactEvent::Created {
            contact_id: id,
            email,
            owner_id,
            created_at: now,
        }));
        
        contact
    }
    
    // =========================================================================
    // Getters (immutable access to internal state)
    // =========================================================================
    
    pub fn id(&self) -> &EntityId { &self.id }
    pub fn email(&self) -> &Email { &self.email }
    pub fn first_name(&self) -> &str { &self.first_name }
    pub fn last_name(&self) -> &str { &self.last_name }
    pub fn full_name(&self) -> String { format!("{} {}", self.first_name, self.last_name) }
    pub fn phone(&self) -> Option<&Phone> { self.phone.as_ref() }
    pub fn mobile(&self) -> Option<&Phone> { self.mobile.as_ref() }
    pub fn title(&self) -> Option<&str> { self.title.as_deref() }
    pub fn department(&self) -> Option<&str> { self.department.as_deref() }
    pub fn address(&self) -> Option<&Address> { self.address.as_ref() }
    pub fn account_id(&self) -> Option<&EntityId> { self.account_id.as_ref() }
    pub fn owner_id(&self) -> &EntityId { &self.owner_id }
    pub fn lead_status(&self) -> &LeadStatus { &self.lead_status }
    pub fn lead_score(&self) -> &LeadScore { &self.lead_score }
    pub fn lifecycle_stage(&self) -> &LifecycleStage { &self.lifecycle_stage }
    pub fn tags(&self) -> &[String] { &self.tags }
    pub fn created_at(&self) -> DateTime<Utc> { self.created_at }
    pub fn updated_at(&self) -> DateTime<Utc> { self.updated_at }
    
    // =========================================================================
    // Business Operations (encapsulated behavior)
    // =========================================================================
    
    /// Update contact information
    pub fn update_info(
        &mut self,
        first_name: Option<String>,
        last_name: Option<String>,
        title: Option<String>,
        department: Option<String>,
    ) {
        if let Some(name) = first_name {
            self.first_name = name;
        }
        if let Some(name) = last_name {
            self.last_name = name;
        }
        if title.is_some() {
            self.title = title;
        }
        if department.is_some() {
            self.department = department;
        }
        self.touch();
    }
    
    /// Set phone number
    pub fn set_phone(&mut self, phone: Phone) {
        self.phone = Some(phone);
        self.touch();
    }
    
    /// Set mobile number
    pub fn set_mobile(&mut self, mobile: Phone) {
        self.mobile = Some(mobile);
        self.touch();
    }
    
    /// Set address
    pub fn set_address(&mut self, address: Address) {
        self.address = Some(address);
        self.touch();
    }
    
    /// Link to account
    pub fn link_to_account(&mut self, account_id: EntityId) {
        self.account_id = Some(account_id);
        self.touch();
    }
    
    /// Qualify the lead
    pub fn qualify(&mut self) -> Result<(), ContactError> {
        if self.lead_status == LeadStatus::Qualified {
            return Err(ContactError::AlreadyQualified);
        }
        
        if self.lead_status == LeadStatus::Unqualified {
            return Err(ContactError::CannotQualifyUnqualified);
        }
        
        let old_status = self.lead_status.clone();
        self.lead_status = LeadStatus::Qualified;
        self.lifecycle_stage = LifecycleStage::SalesQualifiedLead;
        self.touch();
        
        self.raise_event(DomainEvent::Contact(ContactEvent::Qualified {
            contact_id: self.id.clone(),
            previous_status: old_status,
            qualified_at: Utc::now(),
        }));
        
        Ok(())
    }
    
    /// Mark as unqualified
    pub fn disqualify(&mut self, reason: String) {
        self.lead_status = LeadStatus::Unqualified;
        self.custom_fields.insert(
            "disqualification_reason".to_string(),
            serde_json::Value::String(reason),
        );
        self.touch();
    }
    
    /// Convert to customer
    pub fn convert_to_customer(&mut self) -> Result<(), ContactError> {
        if self.lifecycle_stage == LifecycleStage::Customer {
            return Err(ContactError::AlreadyCustomer);
        }
        
        self.lead_status = LeadStatus::Converted;
        self.lifecycle_stage = LifecycleStage::Customer;
        self.touch();
        
        self.raise_event(DomainEvent::Contact(ContactEvent::ConvertedToCustomer {
            contact_id: self.id.clone(),
            converted_at: Utc::now(),
        }));
        
        Ok(())
    }
    
    /// Update lead score
    pub fn update_lead_score(&mut self, score: u8) {
        let old_score = self.lead_score.value();
        self.lead_score = LeadScore::new(score);
        self.touch();
        
        // Raise event if score changed significantly
        if (score as i16 - old_score as i16).abs() >= 10 {
            self.raise_event(DomainEvent::Contact(ContactEvent::LeadScoreChanged {
                contact_id: self.id.clone(),
                old_score,
                new_score: score,
            }));
        }
    }
    
    /// Add tag
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.touch();
        }
    }
    
    /// Remove tag
    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
        self.touch();
    }
    
    /// Record activity
    pub fn record_activity(&mut self) {
        self.last_activity_at = Some(Utc::now());
        self.touch();
    }
    
    /// Transfer ownership
    pub fn transfer_to(&mut self, new_owner_id: EntityId) {
        let old_owner = self.owner_id.clone();
        self.owner_id = new_owner_id.clone();
        self.touch();
        
        self.raise_event(DomainEvent::Contact(ContactEvent::OwnershipTransferred {
            contact_id: self.id.clone(),
            from_owner: old_owner,
            to_owner: new_owner_id,
        }));
    }
    
    // =========================================================================
    // Domain Events
    // =========================================================================
    
    /// Get and clear accumulated domain events
    pub fn take_events(&mut self) -> Vec<DomainEvent> {
        std::mem::take(&mut self.events)
    }
    
    fn raise_event(&mut self, event: DomainEvent) {
        self.events.push(event);
    }
    
    fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

// =============================================================================
// Supporting Types
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LeadStatus {
    New,
    Contacted,
    Qualified,
    Unqualified,
    Nurturing,
    Converted,
}

impl Default for LeadStatus {
    fn default() -> Self { Self::New }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LifecycleStage {
    Subscriber,
    Lead,
    MarketingQualifiedLead,
    SalesQualifiedLead,
    Opportunity,
    Customer,
    Evangelist,
}

impl Default for LifecycleStage {
    fn default() -> Self { Self::Lead }
}

/// Lead score value object (0-100)
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeadScore(u8);

impl LeadScore {
    pub fn new(score: u8) -> Self {
        Self(score.min(100))
    }
    
    pub fn value(&self) -> u8 { self.0 }
    
    pub fn is_hot(&self) -> bool { self.0 >= 80 }
    pub fn is_warm(&self) -> bool { self.0 >= 50 && self.0 < 80 }
    pub fn is_cold(&self) -> bool { self.0 < 50 }
}

impl Default for LeadScore {
    fn default() -> Self { Self::new(0) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactError {
    AlreadyQualified,
    CannotQualifyUnqualified,
    AlreadyCustomer,
}

impl std::error::Error for ContactError {}

impl std::fmt::Display for ContactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyQualified => write!(f, "Contact is already qualified"),
            Self::CannotQualifyUnqualified => write!(f, "Cannot qualify an unqualified contact"),
            Self::AlreadyCustomer => write!(f, "Contact is already a customer"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_contact() -> Contact {
        let email = Email::new("test@example.com").unwrap();
        Contact::create(email, "John", "Doe", EntityId::new())
    }
    
    #[test]
    fn test_contact_creation() {
        let contact = create_test_contact();
        assert_eq!(contact.first_name(), "John");
        assert_eq!(contact.last_name(), "Doe");
        assert_eq!(contact.full_name(), "John Doe");
        assert_eq!(contact.lead_status(), &LeadStatus::New);
    }
    
    #[test]
    fn test_contact_created_event() {
        let mut contact = create_test_contact();
        let events = contact.take_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DomainEvent::Contact(ContactEvent::Created { .. })));
    }
    
    #[test]
    fn test_qualify_contact() {
        let mut contact = create_test_contact();
        contact.take_events(); // Clear creation event
        
        contact.qualify().unwrap();
        
        assert_eq!(contact.lead_status(), &LeadStatus::Qualified);
        assert_eq!(contact.lifecycle_stage(), &LifecycleStage::SalesQualifiedLead);
        
        let events = contact.take_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DomainEvent::Contact(ContactEvent::Qualified { .. })));
    }
    
    #[test]
    fn test_cannot_qualify_twice() {
        let mut contact = create_test_contact();
        contact.qualify().unwrap();
        assert!(matches!(contact.qualify(), Err(ContactError::AlreadyQualified)));
    }
    
    #[test]
    fn test_convert_to_customer() {
        let mut contact = create_test_contact();
        contact.convert_to_customer().unwrap();
        
        assert_eq!(contact.lifecycle_stage(), &LifecycleStage::Customer);
    }
    
    #[test]
    fn test_lead_score() {
        let mut contact = create_test_contact();
        contact.update_lead_score(85);
        
        assert!(contact.lead_score().is_hot());
        assert_eq!(contact.lead_score().value(), 85);
    }
    
    #[test]
    fn test_tags() {
        let mut contact = create_test_contact();
        contact.add_tag("vip");
        contact.add_tag("enterprise");
        
        assert!(contact.tags().contains(&"vip".to_string()));
        
        contact.remove_tag("vip");
        assert!(!contact.tags().contains(&"vip".to_string()));
    }
}
