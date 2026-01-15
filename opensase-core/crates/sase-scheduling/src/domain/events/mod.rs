//! Scheduling events
#[derive(Clone, Debug)]
pub enum DomainEvent { Scheduling(SchedulingEvent) }

#[derive(Clone, Debug)]
pub enum SchedulingEvent { BookingCreated { booking_id: String }, BookingCancelled { booking_id: String }, BookingRescheduled { booking_id: String }, ReminderSent { booking_id: String } }
