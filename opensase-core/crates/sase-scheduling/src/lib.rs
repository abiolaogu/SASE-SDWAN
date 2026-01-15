//! OpenSASE Scheduling Platform
//!
//! Self-hosted scheduling replacing Calendly, Cal.com, Acuity.
//!
//! ## Features
//! - Appointment booking
//! - Availability management
//! - Calendar integrations
//! - Team scheduling
//! - Reminders and notifications

use chrono::{DateTime, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventType {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub duration_minutes: u32,
    pub buffer_before_minutes: u32,
    pub buffer_after_minutes: u32,
    pub color: String,
    pub location: EventLocation,
    pub availability_schedule_id: String,
    pub booking_limits: BookingLimits,
    pub questions: Vec<BookingQuestion>,
    pub confirmations: ConfirmationSettings,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EventLocation {
    InPerson { address: String },
    Phone,
    VideoConference { provider: VideoProvider },
    Custom { instructions: String },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum VideoProvider {
    #[default]
    GoogleMeet,
    Zoom,
    MicrosoftTeams,
    Custom { url: String },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BookingLimits {
    pub min_notice_hours: u32,
    pub max_future_days: u32,
    pub max_per_day: Option<u32>,
    pub max_per_week: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BookingQuestion {
    pub id: String,
    pub question: String,
    pub question_type: QuestionType,
    pub required: bool,
    pub options: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum QuestionType {
    #[default]
    ShortText,
    LongText,
    SingleChoice,
    MultipleChoice,
    Phone,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfirmationSettings {
    pub send_confirmation_email: bool,
    pub send_reminder_email: bool,
    pub reminder_hours_before: Vec<u32>,
    pub redirect_url: Option<String>,
    pub custom_message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilitySchedule {
    pub id: String,
    pub name: String,
    pub timezone: String,
    pub rules: Vec<AvailabilityRule>,
    pub overrides: Vec<DateOverride>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilityRule {
    pub day: Weekday,
    pub intervals: Vec<TimeInterval>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeInterval {
    pub start: NaiveTime,
    pub end: NaiveTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DateOverride {
    pub date: chrono::NaiveDate,
    pub intervals: Vec<TimeInterval>,
    pub is_unavailable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Booking {
    pub id: String,
    pub event_type_id: String,
    pub host_id: String,
    pub invitee: Invitee,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: BookingStatus,
    pub location: EventLocation,
    pub meeting_url: Option<String>,
    pub responses: HashMap<String, String>,
    pub notes: Option<String>,
    pub cancelled_at: Option<DateTime<Utc>>,
    pub cancellation_reason: Option<String>,
    pub rescheduled_from: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Invitee {
    pub name: String,
    pub email: String,
    pub phone: Option<String>,
    pub timezone: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum BookingStatus {
    #[default]
    Confirmed,
    Pending,
    Cancelled,
    NoShow,
    Completed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeSlot {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub available: bool,
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum SchedulingError {
    #[error("Event type not found")]
    EventTypeNotFound,
    
    #[error("Booking not found")]
    BookingNotFound,
    
    #[error("Slot not available")]
    SlotNotAvailable,
    
    #[error("Too short notice")]
    TooShortNotice,
    
    #[error("Booking limit reached")]
    BookingLimitReached,
    
    #[error("Cannot cancel: {0}")]
    CannotCancel(String),
    
    #[error("Calendar sync error: {0}")]
    CalendarSyncError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, SchedulingError>;
