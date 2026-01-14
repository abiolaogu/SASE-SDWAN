//! Alert Generation and Management

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Alert Manager
pub struct AlertManager {
    alerts: Arc<RwLock<Vec<ThreatAlert>>>,
    suppressions: Arc<RwLock<Vec<AlertSuppression>>>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(RwLock::new(Vec::new())),
            suppressions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create alert
    pub fn create_alert(
        &self,
        severity: Severity,
        category: ThreatCategory,
        confidence: f64,
        explanation: String,
    ) -> ThreatAlert {
        let alert = ThreatAlert {
            alert_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            confidence,
            source: AlertSource::MlModel,
            entities: Vec::new(),
            evidence: vec![Evidence {
                evidence_type: "ml_prediction".into(),
                description: explanation,
                data: HashMap::new(),
            }],
            recommended_action: self.get_recommended_action(&category, &severity),
            mitre_attack: self.map_mitre(&category),
            status: AlertStatus::New,
            analyst_feedback: None,
        };

        // Check suppression
        if !self.is_suppressed(&alert) {
            self.alerts.write().push(alert.clone());
        }

        alert
    }

    /// Get all alerts
    pub fn get_alerts(&self, filter: Option<AlertFilter>) -> Vec<ThreatAlert> {
        let alerts = self.alerts.read();
        match filter {
            Some(f) => alerts.iter()
                .filter(|a| f.matches(a))
                .cloned()
                .collect(),
            None => alerts.clone(),
        }
    }

    /// Update alert status
    pub fn update_status(&self, alert_id: Uuid, status: AlertStatus) {
        if let Some(alert) = self.alerts.write().iter_mut().find(|a| a.alert_id == alert_id) {
            alert.status = status;
        }
    }

    /// Add analyst feedback
    pub fn add_feedback(&self, alert_id: Uuid, feedback: AnalystFeedback) {
        if let Some(alert) = self.alerts.write().iter_mut().find(|a| a.alert_id == alert_id) {
            alert.analyst_feedback = Some(feedback);
        }
    }

    /// Add suppression rule
    pub fn add_suppression(&self, suppression: AlertSuppression) {
        self.suppressions.write().push(suppression);
    }

    fn is_suppressed(&self, alert: &ThreatAlert) -> bool {
        self.suppressions.read().iter().any(|s| s.matches(alert))
    }

    fn get_recommended_action(&self, category: &ThreatCategory, severity: &Severity) -> Action {
        match (category, severity) {
            (ThreatCategory::DnsThreat, Severity::Critical) => Action::BlockDomain,
            (ThreatCategory::NetworkAnomaly, Severity::High) => Action::IsolateDevice,
            (ThreatCategory::InsiderThreat, _) => Action::RequireMfa,
            (ThreatCategory::MalwareC2, _) => Action::BlockIp,
            _ => Action::Investigate,
        }
    }

    fn map_mitre(&self, category: &ThreatCategory) -> Option<MitreMapping> {
        match category {
            ThreatCategory::DnsThreat => Some(MitreMapping {
                tactic: "Command and Control".into(),
                technique: "T1071.004".into(),
                name: "DNS".into(),
            }),
            ThreatCategory::MalwareC2 => Some(MitreMapping {
                tactic: "Command and Control".into(),
                technique: "T1071".into(),
                name: "Application Layer Protocol".into(),
            }),
            ThreatCategory::InsiderThreat => Some(MitreMapping {
                tactic: "Exfiltration".into(),
                technique: "T1041".into(),
                name: "Exfiltration Over C2 Channel".into(),
            }),
            _ => None,
        }
    }
}

impl Default for AlertManager {
    fn default() -> Self { Self::new() }
}

/// Threat alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub alert_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: ThreatCategory,
    pub confidence: f64,
    pub source: AlertSource,
    pub entities: Vec<Entity>,
    pub evidence: Vec<Evidence>,
    pub recommended_action: Action,
    pub mitre_attack: Option<MitreMapping>,
    pub status: AlertStatus,
    pub analyst_feedback: Option<AnalystFeedback>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ThreatCategory {
    DnsThreat,
    NetworkAnomaly,
    InsiderThreat,
    MalwareC2,
    DataExfiltration,
    BruteForce,
    Phishing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSource {
    MlModel,
    Signature,
    ThreatIntel,
    Correlation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub entity_type: EntityType,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EntityType {
    Ip,
    Domain,
    User,
    Device,
    Application,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: String,
    pub description: String,
    pub data: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Action {
    BlockIp,
    BlockDomain,
    IsolateDevice,
    RequireMfa,
    NotifyManager,
    Investigate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    InProgress,
    Resolved,
    FalsePositive,
    Escalated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystFeedback {
    pub verdict: Verdict,
    pub notes: String,
    pub analyst_id: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Verdict {
    TruePositive,
    FalsePositive,
    NeedsReview,
}

/// Alert filter
#[derive(Debug, Clone)]
pub struct AlertFilter {
    pub severity: Option<Severity>,
    pub category: Option<ThreatCategory>,
    pub status: Option<AlertStatus>,
}

impl AlertFilter {
    fn matches(&self, alert: &ThreatAlert) -> bool {
        let sev_match = self.severity.map_or(true, |s| std::mem::discriminant(&s) == std::mem::discriminant(&alert.severity));
        let cat_match = self.category.map_or(true, |c| std::mem::discriminant(&c) == std::mem::discriminant(&alert.category));
        let status_match = self.status.map_or(true, |s| std::mem::discriminant(&s) == std::mem::discriminant(&alert.status));
        sev_match && cat_match && status_match
    }
}

/// Alert suppression rule
#[derive(Debug, Clone)]
pub struct AlertSuppression {
    pub category: Option<ThreatCategory>,
    pub entity_value: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl AlertSuppression {
    fn matches(&self, alert: &ThreatAlert) -> bool {
        if Utc::now() > self.expires_at { return false; }
        
        let cat_match = self.category.map_or(true, |c| 
            std::mem::discriminant(&c) == std::mem::discriminant(&alert.category));
        let entity_match = self.entity_value.as_ref().map_or(true, |v| 
            alert.entities.iter().any(|e| &e.value == v));
        
        cat_match && entity_match
    }
}
