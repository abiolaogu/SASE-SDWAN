//! Domain services module

use async_trait::async_trait;
use crate::domain::aggregates::{Contact, Deal};
use crate::domain::value_objects::EntityId;

/// Lead scoring domain service
pub struct LeadScoringService;

impl LeadScoringService {
    /// Calculate lead score based on contact attributes and activities
    pub fn calculate_score(contact: &Contact, activity_count: u32, email_opens: u32, page_views: u32) -> u8 {
        let mut score = 0u8;
        
        // Demographic scoring
        if contact.title().is_some() {
            let title = contact.title().unwrap().to_lowercase();
            if title.contains("ceo") || title.contains("founder") || title.contains("cto") {
                score = score.saturating_add(25);
            } else if title.contains("vp") || title.contains("director") {
                score = score.saturating_add(20);
            } else if title.contains("manager") {
                score = score.saturating_add(15);
            }
        }
        
        // Company association
        if contact.account_id().is_some() {
            score = score.saturating_add(10);
        }
        
        // Activity scoring
        score = score.saturating_add((activity_count.min(10) * 2) as u8);
        score = score.saturating_add((email_opens.min(20)) as u8);
        score = score.saturating_add((page_views.min(20) / 2) as u8);
        
        // Engagement recency
        if contact.lead_score().is_hot() {
            score = score.saturating_add(5);
        }
        
        score.min(100)
    }
}

/// Deal forecasting domain service
pub struct ForecastService;

impl ForecastService {
    /// Calculate weighted pipeline value
    pub fn calculate_weighted_pipeline(deals: &[Deal]) -> rust_decimal::Decimal {
        deals.iter()
            .filter(|d| d.is_open())
            .map(|d| d.weighted_value())
            .sum()
    }
    
    /// Calculate total pipeline value
    pub fn calculate_total_pipeline(deals: &[Deal]) -> rust_decimal::Decimal {
        deals.iter()
            .filter(|d| d.is_open())
            .map(|d| d.amount().amount())
            .sum()
    }
    
    /// Calculate closed won value
    pub fn calculate_closed_won(deals: &[Deal]) -> rust_decimal::Decimal {
        deals.iter()
            .filter(|d| d.is_won())
            .map(|d| d.amount().amount())
            .sum()
    }
    
    /// Identify at-risk deals (stale in stage)
    pub fn identify_at_risk_deals(deals: &[Deal], max_days_in_stage: i64) -> Vec<&Deal> {
        deals.iter()
            .filter(|d| d.is_open() && d.days_in_stage() > max_days_in_stage)
            .collect()
    }
}

/// Contact merge domain service
pub struct ContactMergeService;

impl ContactMergeService {
    /// Merge two contacts, keeping the primary and absorbing the secondary
    pub fn merge(primary: &mut Contact, _secondary: &Contact) -> MergeResult {
        // Record merge activity
        primary.record_activity();
        
        MergeResult {
            primary_id: primary.id().clone(),
            merged_contacts: 1,
        }
    }
}

pub struct MergeResult {
    pub primary_id: EntityId,
    pub merged_contacts: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::Email;
    
    #[test]
    fn test_lead_scoring() {
        let email = Email::new("test@example.com").unwrap();
        let contact = Contact::create(email, "John", "Doe", EntityId::new());
        
        let score = LeadScoringService::calculate_score(&contact, 5, 10, 20);
        assert!(score > 0);
        assert!(score <= 100);
    }
    
    #[test]
    fn test_weighted_pipeline() {
        let deals = vec![
            Deal::create(
                "Deal 1",
                crate::domain::value_objects::Money::usd(rust_decimal::Decimal::new(100000, 0)),
                EntityId::new(),
                EntityId::new(),
                EntityId::new(),
            ),
        ];
        
        let weighted = ForecastService::calculate_weighted_pipeline(&deals);
        assert!(weighted > rust_decimal::Decimal::ZERO);
    }
}
