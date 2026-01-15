//! Automation Aggregate (Workflows)
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct Automation {
    id: String, name: String, status: AutomationStatus,
    trigger: AutomationTrigger, steps: Vec<AutomationStep>,
    enrolled: u64, completed: u64, created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum AutomationStatus { #[default] Draft, Active, Paused, Archived }
#[derive(Clone, Debug)] pub enum AutomationTrigger { FormSubmission { form_id: String }, SegmentEntry { segment_id: String }, DateBased { field: String }, Manual }
#[derive(Clone, Debug)] pub struct AutomationStep { pub id: String, pub step_type: StepType, pub delay_hours: Option<u32>, pub conditions: Vec<String> }
#[derive(Clone, Debug)] pub enum StepType { SendEmail { template_id: String }, Wait { hours: u32 }, IfElse { condition: String }, AddTag { tag: String }, UpdateProperty { field: String, value: String } }

impl Automation {
    pub fn create(name: impl Into<String>, trigger: AutomationTrigger) -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), name: name.into(), status: AutomationStatus::Draft, trigger, steps: vec![], enrolled: 0, completed: 0, created_at: Utc::now() }
    }
    pub fn id(&self) -> &str { &self.id }
    pub fn status(&self) -> &AutomationStatus { &self.status }
    pub fn add_step(&mut self, step: AutomationStep) { self.steps.push(step); }
    pub fn activate(&mut self) { self.status = AutomationStatus::Active; }
    pub fn pause(&mut self) { self.status = AutomationStatus::Paused; }
}
