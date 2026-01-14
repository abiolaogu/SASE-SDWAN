//! Session Management
//!
//! Zero Trust session lifecycle management.

use crate::{Session, SessionStatus, Identity, Device, Resource, TrustLevel};
use std::collections::HashSet;

/// Session manager
pub struct SessionManager {
    /// Active sessions
    sessions: dashmap::DashMap<String, Session>,
    /// User sessions index
    user_sessions: dashmap::DashMap<String, HashSet<String>>,
    /// Default timeout
    timeout_mins: u32,
}

impl SessionManager {
    pub fn new(timeout_mins: u32) -> Self {
        Self {
            sessions: dashmap::DashMap::new(),
            user_sessions: dashmap::DashMap::new(),
            timeout_mins,
        }
    }
    
    /// Create or update session
    pub async fn create_or_update(
        &self,
        identity: &Identity,
        device: &Device,
        resource: &Resource,
    ) -> Session {
        // Check for existing session
        if let Some(sessions) = self.user_sessions.get(&identity.user_id) {
            for session_id in sessions.iter() {
                if let Some(mut session) = self.sessions.get_mut(session_id) {
                    if session.device.id == device.id && session.status == SessionStatus::Active {
                        // Update existing session
                        session.last_activity = chrono::Utc::now();
                        session.active_resources.insert(resource.id.clone());
                        return session.clone();
                    }
                }
            }
        }
        
        // Create new session
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            identity: identity.clone(),
            device: device.clone(),
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(self.timeout_mins as i64),
            trust_level: device.trust_level,
            risk_score: 0.0,
            active_resources: {
                let mut set = HashSet::new();
                set.insert(resource.id.clone());
                set
            },
            status: SessionStatus::Active,
        };
        
        // Store session
        self.sessions.insert(session.id.clone(), session.clone());
        
        // Index by user
        self.user_sessions.entry(identity.user_id.clone())
            .or_insert_with(HashSet::new)
            .insert(session.id.clone());
        
        session
    }
    
    /// Get session by ID
    pub fn get(&self, session_id: &str) -> Option<Session> {
        self.sessions.get(session_id).map(|s| s.clone())
    }
    
    /// Get user's active sessions
    pub fn get_user_sessions(&self, user_id: &str) -> Vec<Session> {
        self.user_sessions.get(user_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.sessions.get(id))
                    .filter(|s| s.status == SessionStatus::Active)
                    .map(|s| s.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Update session activity
    pub async fn touch(&self, session_id: &str) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.last_activity = chrono::Utc::now();
        }
    }
    
    /// Terminate session
    pub async fn terminate(&self, session_id: &str) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.status = SessionStatus::Revoked;
            
            // Remove from user index
            if let Some(mut user_sessions) = self.user_sessions.get_mut(&session.identity.user_id) {
                user_sessions.remove(session_id);
            }
        }
    }
    
    /// Terminate all sessions for user
    pub async fn terminate_all(&self, user_id: &str) {
        if let Some(session_ids) = self.user_sessions.get(user_id) {
            for session_id in session_ids.iter() {
                if let Some(mut session) = self.sessions.get_mut(session_id) {
                    session.status = SessionStatus::Revoked;
                }
            }
        }
        self.user_sessions.remove(user_id);
    }
    
    /// Suspend session (require reauthentication)
    pub async fn suspend(&self, session_id: &str) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.status = SessionStatus::Suspended;
        }
    }
    
    /// Reactivate suspended session
    pub async fn reactivate(&self, session_id: &str, mfa_verified: bool) -> bool {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            if session.status == SessionStatus::Suspended && mfa_verified {
                session.status = SessionStatus::Active;
                session.last_activity = chrono::Utc::now();
                session.expires_at = chrono::Utc::now() + 
                    chrono::Duration::minutes(self.timeout_mins as i64);
                return true;
            }
        }
        false
    }
    
    /// Cleanup expired sessions
    pub async fn cleanup_expired(&self) -> usize {
        let now = chrono::Utc::now();
        let mut removed = 0;
        
        let expired: Vec<String> = self.sessions.iter()
            .filter(|s| now > s.expires_at && s.status == SessionStatus::Active)
            .map(|s| s.id.clone())
            .collect();
        
        for session_id in expired {
            if let Some(mut session) = self.sessions.get_mut(&session_id) {
                session.status = SessionStatus::Expired;
                removed += 1;
                
                if let Some(mut user_sessions) = self.user_sessions.get_mut(&session.identity.user_id) {
                    user_sessions.remove(&session_id);
                }
            }
        }
        
        removed
    }
    
    /// Get session stats
    pub fn stats(&self) -> SessionStats {
        let mut stats = SessionStats::default();
        
        for session in self.sessions.iter() {
            stats.total += 1;
            match session.status {
                SessionStatus::Active => stats.active += 1,
                SessionStatus::Suspended => stats.suspended += 1,
                SessionStatus::Revoked => stats.revoked += 1,
                SessionStatus::Expired => stats.expired += 1,
            }
        }
        
        stats.unique_users = self.user_sessions.len();
        stats
    }
}

#[derive(Debug, Default)]
pub struct SessionStats {
    pub total: usize,
    pub active: usize,
    pub suspended: usize,
    pub revoked: usize,
    pub expired: usize,
    pub unique_users: usize,
}
