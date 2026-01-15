//! Marketing events
#[derive(Clone, Debug)]
pub enum DomainEvent { Campaign(CampaignEvent), Automation(AutomationEvent) }

#[derive(Clone, Debug)]
pub enum CampaignEvent { Created { campaign_id: String }, Sent { campaign_id: String, recipients: u64 }, Opened { campaign_id: String, contact_id: String } }

#[derive(Clone, Debug)]
pub enum AutomationEvent { Activated { automation_id: String }, ContactEnrolled { automation_id: String, contact_id: String }, StepCompleted { automation_id: String, step_id: String, contact_id: String } }
