//! Case Management
//!
//! Security incident case tracking and workflow.

use crate::{SecurityAlert, Severity};
use std::collections::HashMap;

/// Case manager
pub struct CaseManager {
    /// Cases
    cases: dashmap::DashMap<String, Case>,
    /// Case templates
    templates: dashmap::DashMap<String, CaseTemplate>,
    /// Stats
    stats: CaseStats,
}

struct CaseStats {
    total_created: std::sync::atomic::AtomicU64,
    total_resolved: std::sync::atomic::AtomicU64,
    total_time_to_resolve_secs: std::sync::atomic::AtomicU64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Case {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub status: CaseStatus,
    pub priority: CasePriority,
    pub case_type: CaseType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub closed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub due_at: Option<chrono::DateTime<chrono::Utc>>,
    pub owner: Option<String>,
    pub assigned_to: Vec<String>,
    pub alerts: Vec<String>,
    pub observables: Vec<Observable>,
    pub tasks: Vec<CaseTask>,
    pub timeline: Vec<TimelineEvent>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
    pub resolution: Option<CaseResolution>,
    pub tenant_id: String,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum CaseStatus {
    New,
    Open,
    InProgress,
    OnHold,
    Resolved,
    Closed,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum CasePriority {
    P1, // Critical - immediate
    P2, // High - 4 hours
    P3, // Medium - 24 hours
    P4, // Low - 72 hours
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum CaseType {
    SecurityIncident,
    DataBreach,
    Malware,
    Phishing,
    InsiderThreat,
    Vulnerability,
    ComplianceViolation,
    Other,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Observable {
    pub id: String,
    pub observable_type: ObservableType,
    pub value: String,
    pub tlp: Tlp,
    pub is_ioc: bool,
    pub tags: Vec<String>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ObservableType {
    IpAddress,
    Domain,
    Url,
    Hash,
    Email,
    Filename,
    Registry,
    Hostname,
    Username,
    Other,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Tlp {
    White,
    Green,
    Amber,
    Red,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CaseTask {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub status: TaskStatus,
    pub assigned_to: Option<String>,
    pub due_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Cancelled,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: TimelineEventType,
    pub description: String,
    pub actor: Option<String>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum TimelineEventType {
    Created,
    Updated,
    StatusChange,
    Assigned,
    Comment,
    AlertAdded,
    TaskAdded,
    EvidenceAdded,
    Escalated,
    Resolved,
    Closed,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CaseResolution {
    pub resolution_type: ResolutionType,
    pub summary: String,
    pub root_cause: Option<String>,
    pub lessons_learned: Option<String>,
    pub resolved_by: String,
    pub resolved_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ResolutionType {
    TruePositive,
    FalsePositive,
    Benign,
    Inconclusive,
    Duplicate,
    NoAction,
}

#[derive(Clone)]
pub struct CaseTemplate {
    pub id: String,
    pub name: String,
    pub case_type: CaseType,
    pub default_severity: Severity,
    pub default_priority: CasePriority,
    pub default_tasks: Vec<CaseTask>,
    pub playbook_id: Option<String>,
}

impl CaseManager {
    pub fn new() -> Self {
        let manager = Self {
            cases: dashmap::DashMap::new(),
            templates: dashmap::DashMap::new(),
            stats: CaseStats {
                total_created: std::sync::atomic::AtomicU64::new(0),
                total_resolved: std::sync::atomic::AtomicU64::new(0),
                total_time_to_resolve_secs: std::sync::atomic::AtomicU64::new(0),
            },
        };
        
        manager.load_default_templates();
        manager
    }
    
    fn load_default_templates(&self) {
        // Malware incident template
        self.templates.insert("malware-incident".to_string(), CaseTemplate {
            id: "malware-incident".to_string(),
            name: "Malware Incident".to_string(),
            case_type: CaseType::Malware,
            default_severity: Severity::High,
            default_priority: CasePriority::P2,
            default_tasks: vec![
                CaseTask {
                    id: "1".to_string(),
                    title: "Identify affected systems".to_string(),
                    description: Some("List all systems with malware IOCs".to_string()),
                    status: TaskStatus::Pending,
                    assigned_to: None,
                    due_at: None,
                    created_at: chrono::Utc::now(),
                    completed_at: None,
                },
                CaseTask {
                    id: "2".to_string(),
                    title: "Isolate infected hosts".to_string(),
                    description: None,
                    status: TaskStatus::Pending,
                    assigned_to: None,
                    due_at: None,
                    created_at: chrono::Utc::now(),
                    completed_at: None,
                },
                CaseTask {
                    id: "3".to_string(),
                    title: "Collect forensic evidence".to_string(),
                    description: None,
                    status: TaskStatus::Pending,
                    assigned_to: None,
                    due_at: None,
                    created_at: chrono::Utc::now(),
                    completed_at: None,
                },
                CaseTask {
                    id: "4".to_string(),
                    title: "Remediate and restore".to_string(),
                    description: None,
                    status: TaskStatus::Pending,
                    assigned_to: None,
                    due_at: None,
                    created_at: chrono::Utc::now(),
                    completed_at: None,
                },
            ],
            playbook_id: Some("malware-response".to_string()),
        });
        
        // Phishing template
        self.templates.insert("phishing-incident".to_string(), CaseTemplate {
            id: "phishing-incident".to_string(),
            name: "Phishing Incident".to_string(),
            case_type: CaseType::Phishing,
            default_severity: Severity::Medium,
            default_priority: CasePriority::P3,
            default_tasks: vec![
                CaseTask {
                    id: "1".to_string(),
                    title: "Identify recipients".to_string(),
                    description: None,
                    status: TaskStatus::Pending,
                    assigned_to: None,
                    due_at: None,
                    created_at: chrono::Utc::now(),
                    completed_at: None,
                },
                CaseTask {
                    id: "2".to_string(),
                    title: "Block malicious URLs".to_string(),
                    description: None,
                    status: TaskStatus::Pending,
                    assigned_to: None,
                    due_at: None,
                    created_at: chrono::Utc::now(),
                    completed_at: None,
                },
                CaseTask {
                    id: "3".to_string(),
                    title: "Reset compromised credentials".to_string(),
                    description: None,
                    status: TaskStatus::Pending,
                    assigned_to: None,
                    due_at: None,
                    created_at: chrono::Utc::now(),
                    completed_at: None,
                },
            ],
            playbook_id: None,
        });
    }
    
    /// Create case from alert
    pub async fn create_from_alert(&self, alert: &SecurityAlert, template_id: Option<&str>) -> Case {
        let template = template_id
            .and_then(|id| self.templates.get(id))
            .map(|t| t.clone());
        
        let (case_type, tasks) = if let Some(t) = &template {
            (t.case_type, t.default_tasks.clone())
        } else {
            (CaseType::SecurityIncident, vec![])
        };
        
        let case = Case {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("{} - {}", alert.alert_type, &alert.id[..8]),
            description: format!("Auto-created from alert {}", alert.id),
            severity: alert.severity,
            status: CaseStatus::New,
            priority: self.severity_to_priority(alert.severity),
            case_type,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            closed_at: None,
            due_at: Some(self.calculate_due_date(alert.severity)),
            owner: None,
            assigned_to: vec![],
            alerts: vec![alert.id.clone()],
            observables: vec![],
            tasks,
            timeline: vec![TimelineEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: TimelineEventType::Created,
                description: "Case created from security alert".to_string(),
                actor: Some("system".to_string()),
            }],
            tags: vec![],
            custom_fields: HashMap::new(),
            resolution: None,
            tenant_id: "default".to_string(),
        };
        
        self.cases.insert(case.id.clone(), case.clone());
        self.stats.total_created.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        tracing::info!("Created case {} from alert {}", case.id, alert.id);
        
        case
    }
    
    fn severity_to_priority(&self, severity: Severity) -> CasePriority {
        match severity {
            Severity::Critical => CasePriority::P1,
            Severity::High => CasePriority::P2,
            Severity::Medium => CasePriority::P3,
            _ => CasePriority::P4,
        }
    }
    
    fn calculate_due_date(&self, severity: Severity) -> chrono::DateTime<chrono::Utc> {
        let hours = match severity {
            Severity::Critical => 1,
            Severity::High => 4,
            Severity::Medium => 24,
            _ => 72,
        };
        chrono::Utc::now() + chrono::Duration::hours(hours)
    }
    
    /// Update case status
    pub async fn update_status(&self, case_id: &str, status: CaseStatus, actor: &str) {
        if let Some(mut case) = self.cases.get_mut(case_id) {
            let old_status = case.status;
            case.status = status;
            case.updated_at = chrono::Utc::now();
            
            case.timeline.push(TimelineEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: TimelineEventType::StatusChange,
                description: format!("{:?} → {:?}", old_status, status),
                actor: Some(actor.to_string()),
            });
            
            if status == CaseStatus::Resolved || status == CaseStatus::Closed {
                case.closed_at = Some(chrono::Utc::now());
                let duration = (chrono::Utc::now() - case.created_at).num_seconds() as u64;
                self.stats.total_resolved.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats.total_time_to_resolve_secs.fetch_add(duration, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    
    /// Assign case
    pub async fn assign(&self, case_id: &str, assignee: &str, actor: &str) {
        if let Some(mut case) = self.cases.get_mut(case_id) {
            if !case.assigned_to.contains(&assignee.to_string()) {
                case.assigned_to.push(assignee.to_string());
            }
            case.updated_at = chrono::Utc::now();
            
            case.timeline.push(TimelineEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: TimelineEventType::Assigned,
                description: format!("Assigned to {}", assignee),
                actor: Some(actor.to_string()),
            });
        }
    }
    
    /// Add comment
    pub async fn add_comment(&self, case_id: &str, comment: &str, actor: &str) {
        if let Some(mut case) = self.cases.get_mut(case_id) {
            case.timeline.push(TimelineEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: TimelineEventType::Comment,
                description: comment.to_string(),
                actor: Some(actor.to_string()),
            });
            case.updated_at = chrono::Utc::now();
        }
    }
    
    /// Add observable
    pub async fn add_observable(&self, case_id: &str, observable: Observable) {
        if let Some(mut case) = self.cases.get_mut(case_id) {
            case.observables.push(observable);
            case.updated_at = chrono::Utc::now();
        }
    }
    
    /// Resolve case
    pub async fn resolve(&self, case_id: &str, resolution: CaseResolution) {
        if let Some(mut case) = self.cases.get_mut(case_id) {
            case.resolution = Some(resolution);
            case.status = CaseStatus::Resolved;
            case.closed_at = Some(chrono::Utc::now());
            case.updated_at = chrono::Utc::now();
            
            case.timeline.push(TimelineEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: TimelineEventType::Resolved,
                description: "Case resolved".to_string(),
                actor: Some(case.resolution.as_ref().unwrap().resolved_by.clone()),
            });
            
            let duration = (chrono::Utc::now() - case.created_at).num_seconds() as u64;
            self.stats.total_resolved.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.stats.total_time_to_resolve_secs.fetch_add(duration, std::sync::atomic::Ordering::Relaxed);
        }
    }
    
    /// Get case
    pub fn get(&self, case_id: &str) -> Option<Case> {
        self.cases.get(case_id).map(|c| c.clone())
    }
    
    /// Search cases
    pub fn search(&self, query: CaseQuery) -> Vec<Case> {
        self.cases.iter()
            .filter(|c| {
                if let Some(status) = query.status {
                    if c.status != status { return false; }
                }
                if let Some(priority) = query.priority {
                    if c.priority != priority { return false; }
                }
                if let Some(ref assignee) = query.assignee {
                    if !c.assigned_to.contains(assignee) { return false; }
                }
                true
            })
            .map(|c| c.clone())
            .take(query.limit)
            .collect()
    }
    
    /// Get active count
    pub async fn get_active_count(&self) -> u64 {
        self.cases.iter()
            .filter(|c| matches!(c.status, CaseStatus::New | CaseStatus::Open | CaseStatus::InProgress))
            .count() as u64
    }
    
    /// Get MTTR (mean time to respond)
    pub async fn get_mttr(&self) -> f64 {
        let resolved = self.stats.total_resolved.load(std::sync::atomic::Ordering::Relaxed);
        let total_time = self.stats.total_time_to_resolve_secs.load(std::sync::atomic::Ordering::Relaxed);
        
        if resolved > 0 {
            (total_time as f64 / resolved as f64) / 3600.0 // Hours
        } else {
            0.0
        }
    }
}

impl Default for CaseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct CaseQuery {
    pub status: Option<CaseStatus>,
    pub priority: Option<CasePriority>,
    pub assignee: Option<String>,
    pub case_type: Option<CaseType>,
    pub limit: usize,
}

impl CaseQuery {
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }
}
