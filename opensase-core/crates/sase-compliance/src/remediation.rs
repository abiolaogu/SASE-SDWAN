//! Remediation Workflow

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;

/// Remediation manager
pub struct RemediationManager {
    tasks: Arc<RwLock<HashMap<String, RemediationTask>>>,
}

impl RemediationManager {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create remediation task
    pub fn create(&self, control_id: &str, severity: Severity, owner: &str) -> String {
        let due_date = chrono::Utc::now() + match severity {
            Severity::Critical => chrono::Duration::days(7),
            Severity::High => chrono::Duration::days(30),
            Severity::Medium => chrono::Duration::days(90),
            Severity::Low => chrono::Duration::days(180),
        };

        let task = RemediationTask {
            id: Uuid::new_v4().to_string(),
            control_id: control_id.to_string(),
            severity,
            owner: owner.to_string(),
            status: TaskStatus::Open,
            due_date: due_date.date_naive(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            notes: Vec::new(),
            external_ticket: None,
        };

        let id = task.id.clone();
        self.tasks.write().insert(id.clone(), task);
        id
    }

    /// Get task
    pub fn get(&self, id: &str) -> Option<RemediationTask> {
        self.tasks.read().get(id).cloned()
    }

    /// Get overdue tasks
    pub fn overdue(&self) -> Vec<RemediationTask> {
        let today = chrono::Utc::now().date_naive();
        self.tasks.read()
            .values()
            .filter(|t| t.status != TaskStatus::Completed && t.due_date < today)
            .cloned()
            .collect()
    }

    /// Update status
    pub fn update_status(&self, id: &str, status: TaskStatus) {
        if let Some(task) = self.tasks.write().get_mut(id) {
            task.status = status;
            task.updated_at = chrono::Utc::now();
        }
    }

    /// Add note
    pub fn add_note(&self, id: &str, note: &str, author: &str) {
        if let Some(task) = self.tasks.write().get_mut(id) {
            task.notes.push(TaskNote {
                text: note.to_string(),
                author: author.to_string(),
                created_at: chrono::Utc::now(),
            });
            task.updated_at = chrono::Utc::now();
        }
    }

    /// Link external ticket
    pub fn link_ticket(&self, id: &str, ticket: ExternalTicket) {
        if let Some(task) = self.tasks.write().get_mut(id) {
            task.external_ticket = Some(ticket);
            task.updated_at = chrono::Utc::now();
        }
    }
}

impl Default for RemediationManager {
    fn default() -> Self { Self::new() }
}

/// Remediation task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationTask {
    pub id: String,
    pub control_id: String,
    pub severity: Severity,
    pub owner: String,
    pub status: TaskStatus,
    pub due_date: chrono::NaiveDate,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub notes: Vec<TaskNote>,
    pub external_ticket: Option<ExternalTicket>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    Open,
    InProgress,
    Blocked,
    Completed,
    Verified,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskNote {
    pub text: String,
    pub author: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTicket {
    pub system: TicketSystem,
    pub ticket_id: String,
    pub url: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TicketSystem {
    Jira,
    ServiceNow,
    GitHub,
    Other,
}
