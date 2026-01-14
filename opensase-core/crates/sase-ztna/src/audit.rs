//! Audit Logging
//!
//! Comprehensive audit trail for zero trust access.

use crate::{AccessRequest, AccessDecision, Decision};
use std::time::Duration;

/// Audit logger
pub struct AuditLogger {
    /// Audit events
    events: dashmap::DashMap<String, AuditEvent>,
    /// Event retention days
    retention_days: u32,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub id: String,
    pub event_type: AuditEventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub resource_id: Option<String>,
    pub action: Option<String>,
    pub decision: Option<Decision>,
    pub details: std::collections::HashMap<String, String>,
    pub client_ip: Option<std::net::IpAddr>,
    pub processing_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    AccessGranted,
    AccessDenied,
    AccessChallenged,
    AuthenticationSuccess,
    AuthenticationFailure,
    MfaChallenge,
    MfaSuccess,
    MfaFailure,
    SessionCreated,
    SessionTerminated,
    SessionSuspended,
    SessionExpired,
    PolicyViolation,
    RiskSignal,
    DeviceRegistered,
    DeviceBlocked,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            events: dashmap::DashMap::new(),
            retention_days: 90,
        }
    }
    
    /// Log access decision
    pub async fn log_access(
        &self,
        request: &AccessRequest,
        decision: &crate::policy::PolicyDecision,
        processing_time: Duration,
    ) {
        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: match decision.decision {
                Decision::Allow => AuditEventType::AccessGranted,
                Decision::Deny => AuditEventType::AccessDenied,
                Decision::Challenge | Decision::StepUp => AuditEventType::AccessChallenged,
                Decision::Review => AuditEventType::AccessGranted,
            },
            timestamp: chrono::Utc::now(),
            user_id: Some(request.identity.user_id.clone()),
            session_id: request.context.session_id.clone(),
            resource_id: Some(request.resource.id.clone()),
            action: Some(format!("{:?}", request.action)),
            decision: Some(decision.decision),
            details: {
                let mut details = std::collections::HashMap::new();
                details.insert("resource_name".to_string(), request.resource.name.clone());
                details.insert("device_id".to_string(), request.device.id.clone());
                details.insert("reasons".to_string(), decision.reasons.join("; "));
                details
            },
            client_ip: Some(request.context.client_ip),
            processing_time_ms: Some(processing_time.as_millis() as u64),
        };
        
        self.store_event(event);
    }
    
    /// Log access denial
    pub async fn log_denial(&self, request: &AccessRequest, reason: &str) {
        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: AuditEventType::AccessDenied,
            timestamp: chrono::Utc::now(),
            user_id: Some(request.identity.user_id.clone()),
            session_id: request.context.session_id.clone(),
            resource_id: Some(request.resource.id.clone()),
            action: Some(format!("{:?}", request.action)),
            decision: Some(Decision::Deny),
            details: {
                let mut details = std::collections::HashMap::new();
                details.insert("reason".to_string(), reason.to_string());
                details
            },
            client_ip: Some(request.context.client_ip),
            processing_time_ms: None,
        };
        
        self.store_event(event);
    }
    
    /// Log challenge
    pub async fn log_challenge(&self, request: &AccessRequest, risk_score: f64) {
        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: AuditEventType::AccessChallenged,
            timestamp: chrono::Utc::now(),
            user_id: Some(request.identity.user_id.clone()),
            session_id: request.context.session_id.clone(),
            resource_id: Some(request.resource.id.clone()),
            action: None,
            decision: Some(Decision::Challenge),
            details: {
                let mut details = std::collections::HashMap::new();
                details.insert("risk_score".to_string(), format!("{:.1}", risk_score));
                details
            },
            client_ip: Some(request.context.client_ip),
            processing_time_ms: None,
        };
        
        self.store_event(event);
    }
    
    /// Log session termination
    pub async fn log_session_termination(&self, session_id: &str) {
        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: AuditEventType::SessionTerminated,
            timestamp: chrono::Utc::now(),
            user_id: None,
            session_id: Some(session_id.to_string()),
            resource_id: None,
            action: None,
            decision: None,
            details: std::collections::HashMap::new(),
            client_ip: None,
            processing_time_ms: None,
        };
        
        self.store_event(event);
    }
    
    /// Log authentication
    pub async fn log_authentication(&self, user_id: &str, success: bool, method: &str) {
        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: if success {
                AuditEventType::AuthenticationSuccess
            } else {
                AuditEventType::AuthenticationFailure
            },
            timestamp: chrono::Utc::now(),
            user_id: Some(user_id.to_string()),
            session_id: None,
            resource_id: None,
            action: Some(method.to_string()),
            decision: None,
            details: std::collections::HashMap::new(),
            client_ip: None,
            processing_time_ms: None,
        };
        
        self.store_event(event);
    }
    
    fn store_event(&self, event: AuditEvent) {
        tracing::info!(
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            session_id = ?event.session_id,
            "Audit event"
        );
        
        self.events.insert(event.id.clone(), event);
    }
    
    /// Query audit events
    pub fn query(&self, query: AuditQuery) -> Vec<AuditEvent> {
        self.events.iter()
            .filter(|e| {
                // Filter by user
                if let Some(user_id) = &query.user_id {
                    if e.user_id.as_ref() != Some(user_id) {
                        return false;
                    }
                }
                
                // Filter by event type
                if !query.event_types.is_empty() {
                    if !query.event_types.contains(&e.event_type) {
                        return false;
                    }
                }
                
                // Filter by time range
                if let Some(from) = query.from_time {
                    if e.timestamp < from {
                        return false;
                    }
                }
                if let Some(to) = query.to_time {
                    if e.timestamp > to {
                        return false;
                    }
                }
                
                true
            })
            .map(|e| e.clone())
            .take(query.limit)
            .collect()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct AuditQuery {
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub resource_id: Option<String>,
    pub event_types: Vec<AuditEventType>,
    pub from_time: Option<chrono::DateTime<chrono::Utc>>,
    pub to_time: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: usize,
}

impl AuditQuery {
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }
}
