//! Incident Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Incident manager
pub struct IncidentManager {
    /// Incidents
    incidents: Arc<RwLock<HashMap<Uuid, Incident>>>,
    /// On-call schedule
    oncall: Arc<RwLock<OnCallSchedule>>,
}

impl IncidentManager {
    pub fn new() -> Self {
        Self {
            incidents: Arc::new(RwLock::new(HashMap::new())),
            oncall: Arc::new(RwLock::new(OnCallSchedule::default())),
        }
    }

    /// Create incident
    pub fn create(&self, severity: IncidentSeverity, title: &str, description: &str) -> Incident {
        let incident = Incident {
            id: Uuid::new_v4(),
            severity,
            status: IncidentStatus::Open,
            title: title.into(),
            description: description.into(),
            affected_components: vec![],
            timeline: vec![TimelineEntry {
                timestamp: Utc::now(),
                action: "Incident created".into(),
                actor: "system".into(),
            }],
            assignee: self.get_oncall(),
            created_at: Utc::now(),
            resolved_at: None,
            postmortem_url: None,
        };

        self.incidents.write().insert(incident.id, incident.clone());
        self.alert(&incident);
        incident
    }

    /// Update incident status
    pub fn update_status(&self, id: Uuid, status: IncidentStatus, note: &str) {
        if let Some(incident) = self.incidents.write().get_mut(&id) {
            incident.status = status;
            incident.timeline.push(TimelineEntry {
                timestamp: Utc::now(),
                action: format!("Status changed to {:?}: {}", status, note),
                actor: "operator".into(),
            });

            if status == IncidentStatus::Resolved {
                incident.resolved_at = Some(Utc::now());
            }
        }
    }

    /// Add affected component
    pub fn add_affected(&self, id: Uuid, component: &str) {
        if let Some(incident) = self.incidents.write().get_mut(&id) {
            incident.affected_components.push(component.into());
        }
    }

    /// Add timeline entry
    pub fn add_timeline(&self, id: Uuid, action: &str, actor: &str) {
        if let Some(incident) = self.incidents.write().get_mut(&id) {
            incident.timeline.push(TimelineEntry {
                timestamp: Utc::now(),
                action: action.into(),
                actor: actor.into(),
            });
        }
    }

    /// Get active incidents
    pub fn get_active(&self) -> Vec<Incident> {
        self.incidents.read()
            .values()
            .filter(|i| i.status != IncidentStatus::Resolved && i.status != IncidentStatus::Postmortem)
            .cloned()
            .collect()
    }

    /// Get incident
    pub fn get(&self, id: Uuid) -> Option<Incident> {
        self.incidents.read().get(&id).cloned()
    }

    /// Get all incidents
    pub fn get_all(&self) -> Vec<Incident> {
        self.incidents.read().values().cloned().collect()
    }

    fn get_oncall(&self) -> Option<String> {
        let schedule = self.oncall.read();
        schedule.current.clone()
    }

    fn alert(&self, incident: &Incident) {
        tracing::error!(
            "INCIDENT {:?}: {} - {}",
            incident.severity,
            incident.title,
            incident.description
        );
        // In production: PagerDuty, Slack, etc.
    }

    /// Set on-call
    pub fn set_oncall(&self, person: &str) {
        self.oncall.write().current = Some(person.into());
    }

    /// Calculate MTTR
    pub fn calculate_mttr(&self) -> f64 {
        let incidents = self.incidents.read();
        let resolved: Vec<_> = incidents.values()
            .filter(|i| i.resolved_at.is_some())
            .collect();

        if resolved.is_empty() {
            return 0.0;
        }

        let total_minutes: i64 = resolved.iter()
            .map(|i| (i.resolved_at.unwrap() - i.created_at).num_minutes())
            .sum();

        total_minutes as f64 / resolved.len() as f64
    }
}

impl Default for IncidentManager {
    fn default() -> Self { Self::new() }
}

/// Incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub title: String,
    pub description: String,
    pub affected_components: Vec<String>,
    pub timeline: Vec<TimelineEntry>,
    pub assignee: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub postmortem_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentSeverity {
    Sev1, // Critical
    Sev2, // Major
    Sev3, // Minor
    Sev4, // Low
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Identified,
    Monitoring,
    Resolved,
    Postmortem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
}

#[derive(Debug, Clone, Default)]
pub struct OnCallSchedule {
    pub current: Option<String>,
    pub backup: Option<String>,
}
