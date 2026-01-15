//! Scheduling Aggregates
use chrono::{DateTime, Utc};
use crate::domain::value_objects::{TimeSlot, AvailabilitySchedule};
use crate::domain::events::{DomainEvent, SchedulingEvent};

#[derive(Clone, Debug)]
pub struct EventType {
    id: String, name: String, description: Option<String>, duration_minutes: u32,
    color: String, host_id: String, availability: Option<AvailabilitySchedule>,
    buffer_before: u32, buffer_after: u32, max_bookings_per_day: Option<u32>,
    is_active: bool, created_at: DateTime<Utc>,
}

impl EventType {
    pub fn create(name: impl Into<String>, duration_minutes: u32, host_id: impl Into<String>) -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), name: name.into(), description: None, duration_minutes, color: "#3788d8".into(), host_id: host_id.into(), availability: None, buffer_before: 0, buffer_after: 0, max_bookings_per_day: None, is_active: true, created_at: Utc::now() }
    }
    pub fn id(&self) -> &str { &self.id }
    pub fn name(&self) -> &str { &self.name }
    pub fn duration(&self) -> u32 { self.duration_minutes }
    pub fn set_availability(&mut self, schedule: AvailabilitySchedule) { self.availability = Some(schedule); }
    pub fn set_buffer(&mut self, before: u32, after: u32) { self.buffer_before = before; self.buffer_after = after; }
    pub fn deactivate(&mut self) { self.is_active = false; }
}

#[derive(Clone, Debug)]
pub struct Booking {
    id: String, event_type_id: String, host_id: String, invitee_email: String,
    invitee_name: String, time_slot: TimeSlot, status: BookingStatus,
    notes: Option<String>, meeting_url: Option<String>, cancelled_at: Option<DateTime<Utc>>,
    cancel_reason: Option<String>, created_at: DateTime<Utc>, events: Vec<DomainEvent>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum BookingStatus { #[default] Confirmed, Cancelled, Rescheduled, Completed, NoShow }

impl Booking {
    pub fn create(event_type_id: impl Into<String>, host_id: impl Into<String>, invitee_email: impl Into<String>, invitee_name: impl Into<String>, time_slot: TimeSlot) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let mut b = Self { id: id.clone(), event_type_id: event_type_id.into(), host_id: host_id.into(), invitee_email: invitee_email.into(), invitee_name: invitee_name.into(), time_slot, status: BookingStatus::Confirmed, notes: None, meeting_url: None, cancelled_at: None, cancel_reason: None, created_at: Utc::now(), events: vec![] };
        b.raise_event(DomainEvent::Scheduling(SchedulingEvent::BookingCreated { booking_id: id }));
        b
    }
    pub fn id(&self) -> &str { &self.id }
    pub fn status(&self) -> &BookingStatus { &self.status }
    pub fn time_slot(&self) -> &TimeSlot { &self.time_slot }
    pub fn cancel(&mut self, reason: impl Into<String>) { self.status = BookingStatus::Cancelled; self.cancelled_at = Some(Utc::now()); self.cancel_reason = Some(reason.into());
        self.raise_event(DomainEvent::Scheduling(SchedulingEvent::BookingCancelled { booking_id: self.id.clone() }));
    }
    pub fn reschedule(&mut self, new_slot: TimeSlot) { self.time_slot = new_slot; self.status = BookingStatus::Rescheduled;
        self.raise_event(DomainEvent::Scheduling(SchedulingEvent::BookingRescheduled { booking_id: self.id.clone() }));
    }
    pub fn complete(&mut self) { self.status = BookingStatus::Completed; }
    pub fn mark_no_show(&mut self) { self.status = BookingStatus::NoShow; }
    pub fn take_events(&mut self) -> Vec<DomainEvent> { std::mem::take(&mut self.events) }
    fn raise_event(&mut self, e: DomainEvent) { self.events.push(e); }
}

#[derive(Debug, Clone)] pub enum BookingError { SlotNotAvailable, PastTime, AlreadyCancelled }
impl std::error::Error for BookingError {}
impl std::fmt::Display for BookingError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Booking error") } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_booking() {
        let slot = TimeSlot::new(Utc::now() + chrono::Duration::days(1), Utc::now() + chrono::Duration::days(1) + chrono::Duration::hours(1));
        let mut b = Booking::create("evt_1", "host_1", "guest@example.com", "Guest", slot);
        assert_eq!(b.status(), &BookingStatus::Confirmed);
        b.cancel("Conflict");
        assert_eq!(b.status(), &BookingStatus::Cancelled);
    }
}
