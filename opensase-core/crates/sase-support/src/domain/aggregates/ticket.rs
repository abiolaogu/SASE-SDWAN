//! Ticket Aggregate
use chrono::{DateTime, Utc};
use crate::domain::value_objects::{TicketId, Priority, TicketType, SlaPolicy};
use crate::domain::events::{DomainEvent, TicketEvent};

#[derive(Clone, Debug)]
pub struct Ticket {
    id: TicketId, subject: String, description: String, status: TicketStatus,
    priority: Priority, ticket_type: TicketType, requester_id: String,
    assignee_id: Option<String>, group_id: Option<String>, tags: Vec<String>,
    comments: Vec<Comment>, sla: Option<SlaPolicy>, sla_breach_at: Option<DateTime<Utc>>,
    first_responded_at: Option<DateTime<Utc>>, created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>, solved_at: Option<DateTime<Utc>>, events: Vec<DomainEvent>,
}

#[derive(Clone, Debug)] pub struct Comment { pub id: String, pub author_id: String, pub body: String, pub is_public: bool, pub created_at: DateTime<Utc> }
#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum TicketStatus { #[default] New, Open, Pending, OnHold, Solved, Closed }

impl Ticket {
    pub fn create(id: TicketId, subject: impl Into<String>, description: impl Into<String>, requester_id: impl Into<String>) -> Self {
        let now = Utc::now();
        let mut t = Self {
            id: id.clone(), subject: subject.into(), description: description.into(), status: TicketStatus::New,
            priority: Priority::Normal, ticket_type: TicketType::Question, requester_id: requester_id.into(),
            assignee_id: None, group_id: None, tags: vec![], comments: vec![], sla: None, sla_breach_at: None,
            first_responded_at: None, created_at: now, updated_at: now, solved_at: None, events: vec![],
        };
        t.raise_event(DomainEvent::Ticket(TicketEvent::Created { ticket_id: id }));
        t
    }
    
    pub fn id(&self) -> &TicketId { &self.id }
    pub fn status(&self) -> &TicketStatus { &self.status }
    pub fn priority(&self) -> &Priority { &self.priority }
    
    pub fn assign(&mut self, agent_id: impl Into<String>) {
        self.assignee_id = Some(agent_id.into());
        if self.status == TicketStatus::New { self.status = TicketStatus::Open; }
        self.touch();
    }
    
    pub fn add_comment(&mut self, comment: Comment) {
        if self.first_responded_at.is_none() && comment.author_id != self.requester_id { self.first_responded_at = Some(Utc::now()); }
        self.comments.push(comment);
        self.touch();
    }
    
    pub fn solve(&mut self) { self.status = TicketStatus::Solved; self.solved_at = Some(Utc::now()); self.touch();
        self.raise_event(DomainEvent::Ticket(TicketEvent::Solved { ticket_id: self.id.clone() }));
    }
    
    pub fn close(&mut self) { self.status = TicketStatus::Closed; self.touch(); }
    pub fn reopen(&mut self) { if self.status == TicketStatus::Solved || self.status == TicketStatus::Closed { self.status = TicketStatus::Open; self.solved_at = None; self.touch(); } }
    pub fn set_priority(&mut self, priority: Priority) { self.priority = priority; self.touch(); }
    pub fn escalate(&mut self) { self.priority = Priority::Urgent; self.touch(); }
    
    pub fn take_events(&mut self) -> Vec<DomainEvent> { std::mem::take(&mut self.events) }
    fn raise_event(&mut self, e: DomainEvent) { self.events.push(e); }
    fn touch(&mut self) { self.updated_at = Utc::now(); }
}

#[derive(Debug, Clone)] pub enum TicketError { AlreadySolved }
impl std::error::Error for TicketError {}
impl std::fmt::Display for TicketError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Ticket error") } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ticket_workflow() {
        let mut t = Ticket::create(TicketId::new(1001), "Help needed", "Description", "user@example.com");
        t.assign("agent001");
        assert_eq!(t.status(), &TicketStatus::Open);
        t.solve();
        assert_eq!(t.status(), &TicketStatus::Solved);
    }
}
