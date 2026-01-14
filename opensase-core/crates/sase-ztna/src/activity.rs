//! Activity Logger
//!
//! Session recording and activity logging for compliance.

use crate::{Session, Resource, AccessAction};
use std::collections::HashMap;

/// Activity logger for session recording
pub struct ActivityLogger {
    /// Activity logs
    logs: dashmap::DashMap<String, Vec<ActivityEvent>>,
    /// Session recordings
    recordings: dashmap::DashMap<String, SessionRecording>,
    /// DLP alerts
    dlp_alerts: dashmap::DashMap<String, Vec<DlpAlert>>,
}

#[derive(Debug, Clone)]
pub struct ActivityEvent {
    pub id: String,
    pub session_id: String,
    pub tunnel_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: ActivityEventType,
    pub resource: String,
    pub action: String,
    pub details: HashMap<String, String>,
    pub bytes_transferred: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityEventType {
    TunnelCreated,
    TunnelClosed,
    ResourceAccess,
    FileUpload,
    FileDownload,
    ClipboardCopy,
    PrintRequest,
    CommandExecution,
    NetworkRequest,
    ErrorOccurred,
}

#[derive(Debug, Clone)]
pub struct SessionRecording {
    pub id: String,
    pub session_id: String,
    pub user_id: String,
    pub resource_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_secs: u64,
    pub recording_type: RecordingType,
    pub storage_path: Option<String>,
    pub size_bytes: u64,
    pub status: RecordingStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingType {
    ScreenCapture,
    KeystrokeLog,
    NetworkCapture,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingStatus {
    Active,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct DlpAlert {
    pub id: String,
    pub session_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub alert_type: DlpAlertType,
    pub severity: DlpSeverity,
    pub pattern_matched: String,
    pub content_sample: Option<String>,
    pub action_taken: DlpAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAlertType {
    SensitiveData,
    CreditCard,
    SocialSecurity,
    HealthInfo,
    ConfidentialDocument,
    SourceCode,
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAction {
    Logged,
    Blocked,
    Redacted,
    Quarantined,
}

impl ActivityLogger {
    pub fn new() -> Self {
        Self {
            logs: dashmap::DashMap::new(),
            recordings: dashmap::DashMap::new(),
            dlp_alerts: dashmap::DashMap::new(),
        }
    }
    
    /// Log activity event
    pub fn log(&self, event: ActivityEvent) {
        tracing::debug!(
            "Activity: {:?} for session {}",
            event.event_type, event.session_id
        );
        
        self.logs.entry(event.session_id.clone())
            .or_insert_with(Vec::new)
            .push(event);
    }
    
    /// Log resource access
    pub fn log_access(&self, session: &Session, resource: &Resource, action: &AccessAction) {
        let event = ActivityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            tunnel_id: None,
            timestamp: chrono::Utc::now(),
            event_type: ActivityEventType::ResourceAccess,
            resource: resource.name.clone(),
            action: format!("{:?}", action),
            details: HashMap::new(),
            bytes_transferred: None,
        };
        
        self.log(event);
    }
    
    /// Log file transfer
    pub fn log_file_transfer(
        &self,
        session_id: &str,
        filename: &str,
        is_upload: bool,
        size: u64,
    ) {
        let event = ActivityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            tunnel_id: None,
            timestamp: chrono::Utc::now(),
            event_type: if is_upload {
                ActivityEventType::FileUpload
            } else {
                ActivityEventType::FileDownload
            },
            resource: filename.to_string(),
            action: if is_upload { "upload" } else { "download" }.to_string(),
            details: HashMap::new(),
            bytes_transferred: Some(size),
        };
        
        self.log(event);
    }
    
    /// Start session recording
    pub fn start_recording(
        &self,
        session: &Session,
        resource: &Resource,
        recording_type: RecordingType,
    ) -> String {
        let recording = SessionRecording {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            user_id: session.identity.user_id.clone(),
            resource_id: resource.id.clone(),
            started_at: chrono::Utc::now(),
            ended_at: None,
            duration_secs: 0,
            recording_type,
            storage_path: None,
            size_bytes: 0,
            status: RecordingStatus::Active,
        };
        
        let id = recording.id.clone();
        self.recordings.insert(id.clone(), recording);
        
        tracing::info!(
            "Started {:?} recording {} for session {}",
            recording_type, id, session.id
        );
        
        id
    }
    
    /// Stop session recording
    pub fn stop_recording(&self, recording_id: &str) {
        if let Some(mut recording) = self.recordings.get_mut(recording_id) {
            recording.ended_at = Some(chrono::Utc::now());
            recording.duration_secs = 
                (chrono::Utc::now() - recording.started_at).num_seconds() as u64;
            recording.status = RecordingStatus::Completed;
            
            tracing::info!(
                "Stopped recording {} after {} seconds",
                recording_id, recording.duration_secs
            );
        }
    }
    
    /// Log DLP alert
    pub fn log_dlp_alert(&self, alert: DlpAlert) {
        tracing::warn!(
            "DLP Alert {:?} in session {}: {}",
            alert.alert_type, alert.session_id, alert.pattern_matched
        );
        
        self.dlp_alerts.entry(alert.session_id.clone())
            .or_insert_with(Vec::new)
            .push(alert);
    }
    
    /// Check content for DLP violations
    pub fn check_content(&self, session_id: &str, content: &str) -> Vec<DlpAlert> {
        let mut alerts = Vec::new();
        
        // Credit card check
        if self.check_credit_card(content) {
            alerts.push(DlpAlert {
                id: uuid::Uuid::new_v4().to_string(),
                session_id: session_id.to_string(),
                timestamp: chrono::Utc::now(),
                alert_type: DlpAlertType::CreditCard,
                severity: DlpSeverity::High,
                pattern_matched: "Credit card number detected".to_string(),
                content_sample: None,
                action_taken: DlpAction::Blocked,
            });
        }
        
        // SSN check
        if self.check_ssn(content) {
            alerts.push(DlpAlert {
                id: uuid::Uuid::new_v4().to_string(),
                session_id: session_id.to_string(),
                timestamp: chrono::Utc::now(),
                alert_type: DlpAlertType::SocialSecurity,
                severity: DlpSeverity::Critical,
                pattern_matched: "SSN detected".to_string(),
                content_sample: None,
                action_taken: DlpAction::Blocked,
            });
        }
        
        // Log alerts
        for alert in &alerts {
            self.log_dlp_alert(alert.clone());
        }
        
        alerts
    }
    
    fn check_credit_card(&self, content: &str) -> bool {
        // Simple pattern check (in production: use proper regex)
        let digits: String = content.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.len() >= 13 && digits.len() <= 19
    }
    
    fn check_ssn(&self, content: &str) -> bool {
        // SSN pattern: XXX-XX-XXXX
        content.contains('-') && {
            let parts: Vec<&str> = content.split('-').collect();
            parts.len() == 3 && 
            parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
        }
    }
    
    /// Get session activity
    pub fn get_session_activity(&self, session_id: &str) -> Vec<ActivityEvent> {
        self.logs.get(session_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
    
    /// Get session DLP alerts
    pub fn get_session_alerts(&self, session_id: &str) -> Vec<DlpAlert> {
        self.dlp_alerts.get(session_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
}

impl Default for ActivityLogger {
    fn default() -> Self {
        Self::new()
    }
}
