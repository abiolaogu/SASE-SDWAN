//! Scheduling value objects
use chrono::{DateTime, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeSlot { pub start: DateTime<Utc>, pub end: DateTime<Utc> }
impl TimeSlot {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self { Self { start, end } }
    pub fn duration_minutes(&self) -> i64 { (self.end - self.start).num_minutes() }
    pub fn overlaps(&self, other: &TimeSlot) -> bool { self.start < other.end && other.start < self.end }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Availability {
    pub weekday: Weekday,
    pub start_time: NaiveTime,
    pub end_time: NaiveTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilitySchedule {
    pub timezone: String,
    pub rules: Vec<Availability>,
    pub date_overrides: Vec<DateOverride>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DateOverride { pub date: chrono::NaiveDate, pub available: bool, pub slots: Option<Vec<TimeSlot>> }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_time_slot() {
        let s = TimeSlot::new(Utc::now(), Utc::now() + chrono::Duration::hours(1));
        assert_eq!(s.duration_minutes(), 60);
    }
}
