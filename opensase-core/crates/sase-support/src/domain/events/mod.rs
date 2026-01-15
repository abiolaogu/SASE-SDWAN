//! Support domain events
use crate::domain::value_objects::TicketId;

#[derive(Clone, Debug)]
pub enum DomainEvent { Ticket(TicketEvent) }

#[derive(Clone, Debug)]
pub enum TicketEvent {
    Created { ticket_id: TicketId },
    Assigned { ticket_id: TicketId, agent_id: String },
    Solved { ticket_id: TicketId },
    Escalated { ticket_id: TicketId },
    SlaBreach { ticket_id: TicketId },
}
