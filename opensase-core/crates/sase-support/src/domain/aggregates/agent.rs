//! Agent entity
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: AgentRole,
    pub groups: Vec<String>,
    pub skills: Vec<String>,
    pub status: AgentStatus,
    pub max_tickets: u32,
    pub current_tickets: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AgentRole { #[default] Agent, TeamLead, Admin }

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AgentStatus { #[default] Available, Busy, Away, Offline }

impl Agent {
    pub fn new(id: impl Into<String>, name: impl Into<String>, email: impl Into<String>) -> Self {
        Self { id: id.into(), name: name.into(), email: email.into(), role: AgentRole::Agent, groups: vec![], skills: vec![], status: AgentStatus::Available, max_tickets: 20, current_tickets: 0 }
    }
    pub fn can_take_ticket(&self) -> bool { self.status == AgentStatus::Available && self.current_tickets < self.max_tickets }
    pub fn assign_ticket(&mut self) { self.current_tickets += 1; }
    pub fn complete_ticket(&mut self) { if self.current_tickets > 0 { self.current_tickets -= 1; } }
}
