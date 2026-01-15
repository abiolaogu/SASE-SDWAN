//! Support value objects
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TicketId(u64);
impl TicketId {
    pub fn new(id: u64) -> Self { Self(id) }
    pub fn value(&self) -> u64 { self.0 }
}
impl fmt::Display for TicketId { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "#{}", self.0) } }

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum Priority { Low, #[default] Normal, High, Urgent }

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum TicketType { #[default] Question, Incident, Problem, Task }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlaPolicy {
    pub name: String,
    pub first_response_hours: u32,
    pub resolution_hours: u32,
}
impl SlaPolicy {
    pub fn standard() -> Self { Self { name: "Standard".into(), first_response_hours: 24, resolution_hours: 72 } }
    pub fn premium() -> Self { Self { name: "Premium".into(), first_response_hours: 4, resolution_hours: 24 } }
}
