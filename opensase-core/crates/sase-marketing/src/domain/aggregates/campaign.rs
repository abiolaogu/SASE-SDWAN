//! Campaign Aggregate
use chrono::{DateTime, Utc};
use crate::domain::value_objects::{CampaignType, Segment};
use crate::domain::events::{DomainEvent, CampaignEvent};

#[derive(Clone, Debug)]
pub struct Campaign {
    id: String, name: String, campaign_type: CampaignType, status: CampaignStatus,
    subject: Option<String>, content: String, segment: Option<Segment>,
    scheduled_at: Option<DateTime<Utc>>, sent_at: Option<DateTime<Utc>>,
    stats: CampaignStats, created_at: DateTime<Utc>, events: Vec<DomainEvent>,
}

#[derive(Clone, Debug, Default)] pub struct CampaignStats { pub sent: u64, pub delivered: u64, pub opened: u64, pub clicked: u64, pub bounced: u64, pub unsubscribed: u64 }
#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum CampaignStatus { #[default] Draft, Scheduled, Sending, Sent, Paused, Cancelled }

impl Campaign {
    pub fn create(name: impl Into<String>, campaign_type: CampaignType) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        Self { id: id.clone(), name: name.into(), campaign_type, status: CampaignStatus::Draft, subject: None, content: String::new(), segment: None, scheduled_at: None, sent_at: None, stats: CampaignStats::default(), created_at: Utc::now(), events: vec![] }
    }
    
    pub fn id(&self) -> &str { &self.id }
    pub fn status(&self) -> &CampaignStatus { &self.status }
    pub fn stats(&self) -> &CampaignStats { &self.stats }
    
    pub fn set_content(&mut self, subject: impl Into<String>, content: impl Into<String>) { self.subject = Some(subject.into()); self.content = content.into(); }
    pub fn set_segment(&mut self, segment: Segment) { self.segment = Some(segment); }
    
    pub fn schedule(&mut self, at: DateTime<Utc>) -> Result<(), CampaignError> {
        if self.content.is_empty() { return Err(CampaignError::NoContent); }
        self.scheduled_at = Some(at); self.status = CampaignStatus::Scheduled; Ok(())
    }
    
    pub fn send(&mut self) -> Result<(), CampaignError> {
        if self.content.is_empty() { return Err(CampaignError::NoContent); }
        self.status = CampaignStatus::Sending; Ok(())
    }
    
    pub fn complete(&mut self, stats: CampaignStats) {
        self.stats = stats; self.status = CampaignStatus::Sent; self.sent_at = Some(Utc::now());
        self.raise_event(DomainEvent::Campaign(CampaignEvent::Sent { campaign_id: self.id.clone(), recipients: self.stats.sent }));
    }
    
    pub fn cancel(&mut self) { self.status = CampaignStatus::Cancelled; }
    
    pub fn take_events(&mut self) -> Vec<DomainEvent> { std::mem::take(&mut self.events) }
    fn raise_event(&mut self, e: DomainEvent) { self.events.push(e); }
}

#[derive(Debug, Clone)] pub enum CampaignError { NoContent, NoSegment }
impl std::error::Error for CampaignError {}
impl std::fmt::Display for CampaignError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Campaign error") } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_campaign() {
        let mut c = Campaign::create("Welcome Series", CampaignType::Email);
        c.set_content("Welcome!", "Hello and welcome...");
        c.send().unwrap();
        assert_eq!(c.status(), &CampaignStatus::Sending);
    }
}
