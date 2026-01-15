//! Domain Events
//!
//! Events raised by aggregates to communicate state changes.

use chrono::{DateTime, Utc};
use crate::domain::value_objects::{Email, EntityId};
use crate::domain::aggregates::contact::LeadStatus;

/// All domain events in the CRM bounded context
#[derive(Clone, Debug)]
pub enum DomainEvent {
    Contact(ContactEvent),
    Deal(DealEvent),
    Account(AccountEvent),
}

/// Contact-related domain events
#[derive(Clone, Debug)]
pub enum ContactEvent {
    Created {
        contact_id: EntityId,
        email: Email,
        owner_id: EntityId,
        created_at: DateTime<Utc>,
    },
    
    Qualified {
        contact_id: EntityId,
        previous_status: LeadStatus,
        qualified_at: DateTime<Utc>,
    },
    
    ConvertedToCustomer {
        contact_id: EntityId,
        converted_at: DateTime<Utc>,
    },
    
    LeadScoreChanged {
        contact_id: EntityId,
        old_score: u8,
        new_score: u8,
    },
    
    OwnershipTransferred {
        contact_id: EntityId,
        from_owner: EntityId,
        to_owner: EntityId,
    },
    
    Merged {
        primary_contact_id: EntityId,
        merged_contact_id: EntityId,
    },
}

/// Deal-related domain events
#[derive(Clone, Debug)]
pub enum DealEvent {
    Created {
        deal_id: EntityId,
        name: String,
        amount: rust_decimal::Decimal,
        pipeline_id: EntityId,
        owner_id: EntityId,
        created_at: DateTime<Utc>,
    },
    
    StageChanged {
        deal_id: EntityId,
        from_stage: EntityId,
        to_stage: EntityId,
        changed_at: DateTime<Utc>,
    },
    
    Won {
        deal_id: EntityId,
        amount: rust_decimal::Decimal,
        won_at: DateTime<Utc>,
    },
    
    Lost {
        deal_id: EntityId,
        reason: String,
        lost_at: DateTime<Utc>,
    },
    
    AmountChanged {
        deal_id: EntityId,
        old_amount: rust_decimal::Decimal,
        new_amount: rust_decimal::Decimal,
    },
}

/// Account-related domain events
#[derive(Clone, Debug)]
pub enum AccountEvent {
    Created {
        account_id: EntityId,
        name: String,
        owner_id: EntityId,
        created_at: DateTime<Utc>,
    },
    
    ContactLinked {
        account_id: EntityId,
        contact_id: EntityId,
    },
    
    DealLinked {
        account_id: EntityId,
        deal_id: EntityId,
    },
}

impl DomainEvent {
    /// Get the aggregate ID this event belongs to
    pub fn aggregate_id(&self) -> &EntityId {
        match self {
            DomainEvent::Contact(e) => match e {
                ContactEvent::Created { contact_id, .. } => contact_id,
                ContactEvent::Qualified { contact_id, .. } => contact_id,
                ContactEvent::ConvertedToCustomer { contact_id, .. } => contact_id,
                ContactEvent::LeadScoreChanged { contact_id, .. } => contact_id,
                ContactEvent::OwnershipTransferred { contact_id, .. } => contact_id,
                ContactEvent::Merged { primary_contact_id, .. } => primary_contact_id,
            },
            DomainEvent::Deal(e) => match e {
                DealEvent::Created { deal_id, .. } => deal_id,
                DealEvent::StageChanged { deal_id, .. } => deal_id,
                DealEvent::Won { deal_id, .. } => deal_id,
                DealEvent::Lost { deal_id, .. } => deal_id,
                DealEvent::AmountChanged { deal_id, .. } => deal_id,
            },
            DomainEvent::Account(e) => match e {
                AccountEvent::Created { account_id, .. } => account_id,
                AccountEvent::ContactLinked { account_id, .. } => account_id,
                AccountEvent::DealLinked { account_id, .. } => account_id,
            },
        }
    }
    
    /// Get event type name
    pub fn event_type(&self) -> &'static str {
        match self {
            DomainEvent::Contact(e) => match e {
                ContactEvent::Created { .. } => "contact.created",
                ContactEvent::Qualified { .. } => "contact.qualified",
                ContactEvent::ConvertedToCustomer { .. } => "contact.converted_to_customer",
                ContactEvent::LeadScoreChanged { .. } => "contact.lead_score_changed",
                ContactEvent::OwnershipTransferred { .. } => "contact.ownership_transferred",
                ContactEvent::Merged { .. } => "contact.merged",
            },
            DomainEvent::Deal(e) => match e {
                DealEvent::Created { .. } => "deal.created",
                DealEvent::StageChanged { .. } => "deal.stage_changed",
                DealEvent::Won { .. } => "deal.won",
                DealEvent::Lost { .. } => "deal.lost",
                DealEvent::AmountChanged { .. } => "deal.amount_changed",
            },
            DomainEvent::Account(e) => match e {
                AccountEvent::Created { .. } => "account.created",
                AccountEvent::ContactLinked { .. } => "account.contact_linked",
                AccountEvent::DealLinked { .. } => "account.deal_linked",
            },
        }
    }
}
