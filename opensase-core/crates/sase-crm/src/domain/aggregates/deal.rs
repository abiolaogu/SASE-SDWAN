//! Deal Aggregate
//!
//! Rich aggregate root for sales opportunity management.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::domain::value_objects::{EntityId, Money, Currency};
use crate::domain::events::{DomainEvent, DealEvent};

/// Deal aggregate root
#[derive(Clone, Debug)]
pub struct Deal {
    id: EntityId,
    name: String,
    amount: Money,
    pipeline_id: EntityId,
    stage_id: EntityId,
    probability: Probability,
    expected_close_date: Option<NaiveDate>,
    actual_close_date: Option<NaiveDate>,
    contact_id: Option<EntityId>,
    account_id: Option<EntityId>,
    owner_id: EntityId,
    deal_type: DealType,
    status: DealStatus,
    lost_reason: Option<String>,
    next_step: Option<String>,
    competitors: Vec<Competitor>,
    products: Vec<DealProduct>,
    tags: Vec<String>,
    custom_fields: HashMap<String, serde_json::Value>,
    stage_history: Vec<StageChange>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
    events: Vec<DomainEvent>,
}

impl Deal {
    /// Create a new deal
    pub fn create(
        name: impl Into<String>,
        amount: Money,
        pipeline_id: EntityId,
        initial_stage_id: EntityId,
        owner_id: EntityId,
    ) -> Self {
        let now = Utc::now();
        let id = EntityId::new();
        
        let mut deal = Self {
            id: id.clone(),
            name: name.into(),
            amount: amount.clone(),
            pipeline_id: pipeline_id.clone(),
            stage_id: initial_stage_id,
            probability: Probability::new(10),
            expected_close_date: None,
            actual_close_date: None,
            contact_id: None,
            account_id: None,
            owner_id: owner_id.clone(),
            deal_type: DealType::NewBusiness,
            status: DealStatus::Open,
            lost_reason: None,
            next_step: None,
            competitors: vec![],
            products: vec![],
            tags: vec![],
            custom_fields: HashMap::new(),
            stage_history: vec![],
            created_at: now,
            updated_at: now,
            closed_at: None,
            events: vec![],
        };
        
        deal.raise_event(DomainEvent::Deal(DealEvent::Created {
            deal_id: id,
            name: deal.name.clone(),
            amount: amount.amount(),
            pipeline_id,
            owner_id,
            created_at: now,
        }));
        
        deal
    }
    
    // =========================================================================
    // Getters
    // =========================================================================
    
    pub fn id(&self) -> &EntityId { &self.id }
    pub fn name(&self) -> &str { &self.name }
    pub fn amount(&self) -> &Money { &self.amount }
    pub fn pipeline_id(&self) -> &EntityId { &self.pipeline_id }
    pub fn stage_id(&self) -> &EntityId { &self.stage_id }
    pub fn probability(&self) -> &Probability { &self.probability }
    pub fn expected_close_date(&self) -> Option<NaiveDate> { self.expected_close_date }
    pub fn contact_id(&self) -> Option<&EntityId> { self.contact_id.as_ref() }
    pub fn account_id(&self) -> Option<&EntityId> { self.account_id.as_ref() }
    pub fn owner_id(&self) -> &EntityId { &self.owner_id }
    pub fn status(&self) -> &DealStatus { &self.status }
    pub fn is_open(&self) -> bool { self.status == DealStatus::Open }
    pub fn is_won(&self) -> bool { self.status == DealStatus::Won }
    pub fn is_lost(&self) -> bool { self.status == DealStatus::Lost }
    pub fn products(&self) -> &[DealProduct] { &self.products }
    pub fn stage_history(&self) -> &[StageChange] { &self.stage_history }
    
    /// Calculate weighted value (amount * probability)
    pub fn weighted_value(&self) -> Decimal {
        self.amount.amount() * Decimal::from(self.probability.value()) / Decimal::from(100)
    }
    
    // =========================================================================
    // Business Operations
    // =========================================================================
    
    /// Move deal to a new stage
    pub fn move_to_stage(&mut self, new_stage_id: EntityId, probability: u8) -> Result<(), DealError> {
        if !self.is_open() {
            return Err(DealError::DealNotOpen);
        }
        
        if self.stage_id == new_stage_id {
            return Err(DealError::AlreadyInStage);
        }
        
        let old_stage = self.stage_id.clone();
        let now = Utc::now();
        
        // Record stage change
        self.stage_history.push(StageChange {
            from_stage: old_stage.clone(),
            to_stage: new_stage_id.clone(),
            changed_at: now,
        });
        
        self.stage_id = new_stage_id.clone();
        self.probability = Probability::new(probability);
        self.touch();
        
        self.raise_event(DomainEvent::Deal(DealEvent::StageChanged {
            deal_id: self.id.clone(),
            from_stage: old_stage,
            to_stage: new_stage_id,
            changed_at: now,
        }));
        
        Ok(())
    }
    
    /// Update deal amount
    pub fn update_amount(&mut self, new_amount: Money) -> Result<(), DealError> {
        if !self.is_open() {
            return Err(DealError::DealNotOpen);
        }
        
        if !self.amount.same_currency(&new_amount) {
            return Err(DealError::CurrencyMismatch);
        }
        
        let old_amount = self.amount.amount();
        self.amount = new_amount;
        self.touch();
        
        self.raise_event(DomainEvent::Deal(DealEvent::AmountChanged {
            deal_id: self.id.clone(),
            old_amount,
            new_amount: self.amount.amount(),
        }));
        
        Ok(())
    }
    
    /// Close deal as won
    pub fn close_won(&mut self) -> Result<(), DealError> {
        if !self.is_open() {
            return Err(DealError::DealNotOpen);
        }
        
        let now = Utc::now();
        
        self.status = DealStatus::Won;
        self.probability = Probability::new(100);
        self.actual_close_date = Some(now.date_naive());
        self.closed_at = Some(now);
        self.touch();
        
        self.raise_event(DomainEvent::Deal(DealEvent::Won {
            deal_id: self.id.clone(),
            amount: self.amount.amount(),
            won_at: now,
        }));
        
        Ok(())
    }
    
    /// Close deal as lost
    pub fn close_lost(&mut self, reason: impl Into<String>) -> Result<(), DealError> {
        if !self.is_open() {
            return Err(DealError::DealNotOpen);
        }
        
        let now = Utc::now();
        let reason = reason.into();
        
        self.status = DealStatus::Lost;
        self.probability = Probability::new(0);
        self.lost_reason = Some(reason.clone());
        self.actual_close_date = Some(now.date_naive());
        self.closed_at = Some(now);
        self.touch();
        
        self.raise_event(DomainEvent::Deal(DealEvent::Lost {
            deal_id: self.id.clone(),
            reason,
            lost_at: now,
        }));
        
        Ok(())
    }
    
    /// Reopen a closed deal
    pub fn reopen(&mut self) -> Result<(), DealError> {
        if self.is_open() {
            return Err(DealError::AlreadyOpen);
        }
        
        self.status = DealStatus::Open;
        self.probability = Probability::new(10);
        self.lost_reason = None;
        self.actual_close_date = None;
        self.closed_at = None;
        self.touch();
        
        Ok(())
    }
    
    /// Add product to deal
    pub fn add_product(&mut self, product: DealProduct) {
        self.products.push(product);
        self.recalculate_amount();
        self.touch();
    }
    
    /// Remove product from deal
    pub fn remove_product(&mut self, product_id: &EntityId) {
        self.products.retain(|p| &p.product_id != product_id);
        self.recalculate_amount();
        self.touch();
    }
    
    /// Link to contact
    pub fn link_contact(&mut self, contact_id: EntityId) {
        self.contact_id = Some(contact_id);
        self.touch();
    }
    
    /// Link to account
    pub fn link_account(&mut self, account_id: EntityId) {
        self.account_id = Some(account_id);
        self.touch();
    }
    
    /// Set expected close date
    pub fn set_expected_close_date(&mut self, date: NaiveDate) {
        self.expected_close_date = Some(date);
        self.touch();
    }
    
    /// Set next step
    pub fn set_next_step(&mut self, next_step: impl Into<String>) {
        self.next_step = Some(next_step.into());
        self.touch();
    }
    
    /// Add competitor
    pub fn add_competitor(&mut self, competitor: Competitor) {
        self.competitors.push(competitor);
        self.touch();
    }
    
    /// Get days in current stage
    pub fn days_in_stage(&self) -> i64 {
        if let Some(last_change) = self.stage_history.last() {
            (Utc::now() - last_change.changed_at).num_days()
        } else {
            (Utc::now() - self.created_at).num_days()
        }
    }
    
    // =========================================================================
    // Private
    // =========================================================================
    
    fn recalculate_amount(&mut self) {
        if !self.products.is_empty() {
            let total: Decimal = self.products.iter()
                .map(|p| p.total())
                .sum();
            self.amount = Money::new(total, self.amount.currency().clone());
        }
    }
    
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
pub enum DealStatus {
    Open,
    Won,
    Lost,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DealType {
    NewBusiness,
    Renewal,
    Upsell,
    CrossSell,
}

/// Probability value object (0-100%)
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Probability(u8);

impl Probability {
    pub fn new(value: u8) -> Self {
        Self(value.min(100))
    }
    
    pub fn value(&self) -> u8 { self.0 }
}

#[derive(Clone, Debug)]
pub struct StageChange {
    pub from_stage: EntityId,
    pub to_stage: EntityId,
    pub changed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct Competitor {
    pub name: String,
    pub strengths: Vec<String>,
    pub weaknesses: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DealProduct {
    pub product_id: EntityId,
    pub name: String,
    pub quantity: u32,
    pub unit_price: Decimal,
    pub discount_percent: Decimal,
}

impl DealProduct {
    pub fn total(&self) -> Decimal {
        let subtotal = self.unit_price * Decimal::from(self.quantity);
        let discount = subtotal * self.discount_percent / Decimal::from(100);
        subtotal - discount
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DealError {
    DealNotOpen,
    AlreadyOpen,
    AlreadyInStage,
    CurrencyMismatch,
}

impl std::error::Error for DealError {}

impl std::fmt::Display for DealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DealNotOpen => write!(f, "Deal is not open"),
            Self::AlreadyOpen => write!(f, "Deal is already open"),
            Self::AlreadyInStage => write!(f, "Deal is already in this stage"),
            Self::CurrencyMismatch => write!(f, "Currency mismatch"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_deal() -> Deal {
        Deal::create(
            "Big Enterprise Deal",
            Money::usd(Decimal::new(100000, 0)),
            EntityId::new(),
            EntityId::new(),
            EntityId::new(),
        )
    }
    
    #[test]
    fn test_deal_creation() {
        let deal = create_test_deal();
        assert_eq!(deal.name(), "Big Enterprise Deal");
        assert!(deal.is_open());
        assert!(!deal.is_won());
    }
    
    #[test]
    fn test_move_stage() {
        let mut deal = create_test_deal();
        let new_stage = EntityId::new();
        
        deal.move_to_stage(new_stage.clone(), 50).unwrap();
        
        assert_eq!(deal.stage_id(), &new_stage);
        assert_eq!(deal.probability().value(), 50);
        assert_eq!(deal.stage_history().len(), 1);
    }
    
    #[test]
    fn test_close_won() {
        let mut deal = create_test_deal();
        deal.close_won().unwrap();
        
        assert!(deal.is_won());
        assert_eq!(deal.probability().value(), 100);
        assert!(deal.actual_close_date.is_some());
    }
    
    #[test]
    fn test_close_lost() {
        let mut deal = create_test_deal();
        deal.close_lost("Budget constraints").unwrap();
        
        assert!(deal.is_lost());
        assert_eq!(deal.probability().value(), 0);
    }
    
    #[test]
    fn test_cannot_modify_closed_deal() {
        let mut deal = create_test_deal();
        deal.close_won().unwrap();
        
        let new_stage = EntityId::new();
        assert!(matches!(
            deal.move_to_stage(new_stage, 50),
            Err(DealError::DealNotOpen)
        ));
    }
    
    #[test]
    fn test_weighted_value() {
        let mut deal = create_test_deal();
        deal.move_to_stage(EntityId::new(), 50).unwrap();
        
        // $100,000 * 50% = $50,000
        assert_eq!(deal.weighted_value(), Decimal::new(50000, 0));
    }
}
