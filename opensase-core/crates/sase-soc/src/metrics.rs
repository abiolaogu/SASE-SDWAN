//! SOC Metrics and Reporting
//!
//! KPIs, dashboards, and compliance metrics.

use crate::Severity;
use std::collections::HashMap;

pub struct SocMetrics {
    events: dashmap::DashMap<String, EventMetric>,
    alerts: dashmap::DashMap<String, AlertMetric>,
    cases: dashmap::DashMap<String, CaseMetric>,
}

struct EventMetric {
    count: u64,
    severity: Severity,
    timestamp: chrono::DateTime<chrono::Utc>,
}

struct AlertMetric {
    severity: Severity,
    created_at: chrono::DateTime<chrono::Utc>,
    detected_at: chrono::DateTime<chrono::Utc>,
    status: String,
}

struct CaseMetric {
    severity: Severity,
    created_at: chrono::DateTime<chrono::Utc>,
    first_response_at: Option<chrono::DateTime<chrono::Utc>>,
    resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    sla_breached: bool,
}

impl SocMetrics {
    pub fn new() -> Self {
        Self {
            events: dashmap::DashMap::new(),
            alerts: dashmap::DashMap::new(),
            cases: dashmap::DashMap::new(),
        }
    }
    
    /// Generate SOC metrics report
    pub fn generate_report(&self, period: DateRange) -> SocMetricsReport {
        let alerts_in_period: Vec<_> = self.alerts.iter()
            .filter(|a| a.created_at >= period.start && a.created_at <= period.end)
            .collect();
        
        let cases_in_period: Vec<_> = self.cases.iter()
            .filter(|c| c.created_at >= period.start && c.created_at <= period.end)
            .collect();
        
        // Calculate MTTD (Mean Time to Detect)
        let mttd = if !alerts_in_period.is_empty() {
            let total_ms: i64 = alerts_in_period.iter()
                .map(|a| (a.created_at - a.detected_at).num_milliseconds().abs())
                .sum();
            total_ms as f64 / alerts_in_period.len() as f64 / 1000.0 / 60.0 // minutes
        } else {
            0.0
        };
        
        // Calculate MTTR (Mean Time to Respond)
        let mttr = {
            let responded: Vec<_> = cases_in_period.iter()
                .filter(|c| c.first_response_at.is_some())
                .collect();
            if !responded.is_empty() {
                let total_ms: i64 = responded.iter()
                    .filter_map(|c| c.first_response_at.map(|r| (r - c.created_at).num_milliseconds()))
                    .sum();
                total_ms as f64 / responded.len() as f64 / 1000.0 / 60.0 // minutes
            } else {
                0.0
            }
        };
        
        // Calculate MTTR-Resolve
        let mttr_resolve = {
            let resolved: Vec<_> = cases_in_period.iter()
                .filter(|c| c.resolved_at.is_some())
                .collect();
            if !resolved.is_empty() {
                let total_ms: i64 = resolved.iter()
                    .filter_map(|c| c.resolved_at.map(|r| (r - c.created_at).num_milliseconds()))
                    .sum();
                total_ms as f64 / resolved.len() as f64 / 1000.0 / 60.0 / 60.0 // hours
            } else {
                0.0
            }
        };
        
        // SLA compliance
        let sla_compliance = {
            let total = cases_in_period.len();
            let breached = cases_in_period.iter().filter(|c| c.sla_breached).count();
            if total > 0 {
                ((total - breached) as f64 / total as f64) * 100.0
            } else {
                100.0
            }
        };
        
        // Alerts by severity
        let mut alerts_by_severity = HashMap::new();
        for alert in &alerts_in_period {
            *alerts_by_severity.entry(format!("{:?}", alert.severity)).or_insert(0u64) += 1;
        }
        
        SocMetricsReport {
            period,
            total_events: self.events.len() as u64,
            total_alerts: alerts_in_period.len() as u64,
            total_cases: cases_in_period.len() as u64,
            alerts_by_severity,
            mean_time_to_detect_minutes: mttd,
            mean_time_to_respond_minutes: mttr,
            mean_time_to_resolve_hours: mttr_resolve,
            sla_compliance_percent: sla_compliance,
        }
    }
    
    pub fn record_event(&self, id: &str, severity: Severity) {
        self.events.insert(id.to_string(), EventMetric {
            count: 1,
            severity,
            timestamp: chrono::Utc::now(),
        });
    }
    
    pub fn record_alert(&self, id: &str, severity: Severity, detected_at: chrono::DateTime<chrono::Utc>) {
        self.alerts.insert(id.to_string(), AlertMetric {
            severity,
            created_at: chrono::Utc::now(),
            detected_at,
            status: "new".to_string(),
        });
    }
    
    pub fn record_case(&self, id: &str, severity: Severity) {
        self.cases.insert(id.to_string(), CaseMetric {
            severity,
            created_at: chrono::Utc::now(),
            first_response_at: None,
            resolved_at: None,
            sla_breached: false,
        });
    }
    
    pub fn record_first_response(&self, case_id: &str) {
        if let Some(mut case) = self.cases.get_mut(case_id) {
            case.first_response_at = Some(chrono::Utc::now());
        }
    }
    
    pub fn record_case_resolved(&self, case_id: &str) {
        if let Some(mut case) = self.cases.get_mut(case_id) {
            case.resolved_at = Some(chrono::Utc::now());
        }
    }
}

impl Default for SocMetrics {
    fn default() -> Self { Self::new() }
}

#[derive(Clone)]
pub struct DateRange {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

impl DateRange {
    pub fn last_24_hours() -> Self {
        Self {
            start: chrono::Utc::now() - chrono::Duration::hours(24),
            end: chrono::Utc::now(),
        }
    }
    
    pub fn last_7_days() -> Self {
        Self {
            start: chrono::Utc::now() - chrono::Duration::days(7),
            end: chrono::Utc::now(),
        }
    }
    
    pub fn last_30_days() -> Self {
        Self {
            start: chrono::Utc::now() - chrono::Duration::days(30),
            end: chrono::Utc::now(),
        }
    }
}

#[derive(Clone, serde::Serialize)]
pub struct SocMetricsReport {
    pub period: DateRange,
    pub total_events: u64,
    pub total_alerts: u64,
    pub total_cases: u64,
    pub alerts_by_severity: HashMap<String, u64>,
    pub mean_time_to_detect_minutes: f64,
    pub mean_time_to_respond_minutes: f64,
    pub mean_time_to_resolve_hours: f64,
    pub sla_compliance_percent: f64,
}

impl serde::Serialize for DateRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DateRange", 2)?;
        state.serialize_field("start", &self.start.to_rfc3339())?;
        state.serialize_field("end", &self.end.to_rfc3339())?;
        state.end()
    }
}
