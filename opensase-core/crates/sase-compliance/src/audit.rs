//! Audit Trail (Tamper-Evident)

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use uuid::Uuid;

/// Audit trail with hash chain
pub struct AuditTrail {
    events: Arc<RwLock<Vec<AuditEvent>>>,
    last_hash: Arc<RwLock<String>>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            last_hash: Arc::new(RwLock::new("genesis".into())),
        }
    }

    /// Log audit event
    pub fn log(&self, event_type: AuditEventType, actor: &str, target: &str, details: &str) {
        let prev_hash = self.last_hash.read().clone();
        
        let event = AuditEvent::new(event_type, actor, target, details, &prev_hash);
        let new_hash = event.hash.clone();
        
        self.events.write().push(event);
        *self.last_hash.write() = new_hash;
    }

    /// Get events
    pub fn get_events(&self, filter: Option<AuditFilter>) -> Vec<AuditEvent> {
        let events = self.events.read();
        match filter {
            Some(f) => events.iter().filter(|e| f.matches(e)).cloned().collect(),
            None => events.clone(),
        }
    }

    /// Verify chain integrity
    pub fn verify_integrity(&self) -> IntegrityResult {
        let events = self.events.read();
        let mut prev_hash = "genesis".to_string();
        let mut valid_count = 0;
        
        for event in events.iter() {
            if event.prev_hash != prev_hash {
                return IntegrityResult {
                    valid: false,
                    checked_count: valid_count,
                    error: Some(format!("Hash chain broken at event {}", event.id)),
                };
            }
            
            // Verify event hash
            let computed = event.compute_hash(&prev_hash);
            if computed != event.hash {
                return IntegrityResult {
                    valid: false,
                    checked_count: valid_count,
                    error: Some(format!("Event {} hash mismatch", event.id)),
                };
            }
            
            prev_hash = event.hash.clone();
            valid_count += 1;
        }
        
        IntegrityResult {
            valid: true,
            checked_count: valid_count,
            error: None,
        }
    }

    /// Export to format
    pub fn export(&self, format: ExportFormat) -> String {
        let events = self.events.read();
        match format {
            ExportFormat::Json => serde_json::to_string_pretty(&*events).unwrap_or_default(),
            ExportFormat::Csv => self.to_csv(&events),
            ExportFormat::Cef => self.to_cef(&events),
        }
    }

    fn to_csv(&self, events: &[AuditEvent]) -> String {
        let mut csv = "timestamp,event_type,actor,target,details\n".to_string();
        for e in events {
            csv.push_str(&format!("{},{:?},{},{},{}\n",
                e.timestamp, e.event_type, e.actor, e.target, e.details));
        }
        csv
    }

    fn to_cef(&self, events: &[AuditEvent]) -> String {
        let mut cef = String::new();
        for e in events {
            cef.push_str(&format!(
                "CEF:0|OpenSASE|OCE|1.0|{}|{}|5|src={} dst={} msg={}\n",
                e.event_type as u8, e.event_type as u8, e.actor, e.target, e.details
            ));
        }
        cef
    }
}

impl Default for AuditTrail {
    fn default() -> Self { Self::new() }
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub actor: String,
    pub target: String,
    pub details: String,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEvent {
    fn new(event_type: AuditEventType, actor: &str, target: &str, details: &str, prev_hash: &str) -> Self {
        let id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now();
        
        let mut event = Self {
            id: id.clone(),
            timestamp,
            event_type,
            actor: actor.to_string(),
            target: target.to_string(),
            details: details.to_string(),
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
        };
        
        event.hash = event.compute_hash(prev_hash);
        event
    }

    fn compute_hash(&self, prev_hash: &str) -> String {
        let data = format!("{}|{}|{:?}|{}|{}|{}|{}",
            self.id, self.timestamp, self.event_type, 
            self.actor, self.target, self.details, prev_hash);
        hex::encode(Sha256::digest(data.as_bytes()))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuditEventType {
    AdminAction = 1,
    PolicyChange = 2,
    AccessEvent = 3,
    SecurityIncident = 4,
    ConfigChange = 5,
    UserLogin = 6,
    UserLogout = 7,
    DataAccess = 8,
}

/// Audit filter
pub struct AuditFilter {
    pub event_type: Option<AuditEventType>,
    pub actor: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuditFilter {
    fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(t) = &self.event_type {
            if std::mem::discriminant(t) != std::mem::discriminant(&event.event_type) {
                return false;
            }
        }
        if let Some(a) = &self.actor {
            if !event.actor.contains(a) { return false; }
        }
        if let Some(s) = &self.start_time {
            if event.timestamp < *s { return false; }
        }
        if let Some(e) = &self.end_time {
            if event.timestamp > *e { return false; }
        }
        true
    }
}

/// Integrity check result
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    pub valid: bool,
    pub checked_count: usize,
    pub error: Option<String>,
}

/// Export format
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    Csv,
    Cef,
}
