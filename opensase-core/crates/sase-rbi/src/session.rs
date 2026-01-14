//! Session Management
//!
//! Browser isolation session lifecycle and persistence.

use crate::{IsolationSession, SessionConfig, SessionStatus, SessionMetrics, IsolationMode, Viewport};
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Session manager for RBI
pub struct SessionManager {
    sessions: DashMap<String, ManagedSession>,
    config: SessionManagerConfig,
}

struct ManagedSession {
    session: IsolationSession,
    last_activity: Instant,
    activity_count: u64,
}

#[derive(Debug, Clone)]
pub struct SessionManagerConfig {
    pub max_sessions: usize,
    pub idle_timeout: Duration,
    pub max_session_duration: Duration,
    pub cleanup_interval: Duration,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            idle_timeout: Duration::from_secs(900),       // 15 min
            max_session_duration: Duration::from_secs(28800), // 8 hours
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

impl SessionManager {
    pub fn new(config: SessionManagerConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            config,
        }
    }
    
    /// Create new session
    pub fn create(&self, user_id: &str, config: SessionConfig) -> Result<IsolationSession, String> {
        if self.sessions.len() >= self.config.max_sessions {
            return Err("Maximum sessions reached".to_string());
        }
        
        let session = IsolationSession {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            container_id: String::new(),
            pop_location: String::new(),
            mode: IsolationMode::PixelPush,
            status: SessionStatus::Creating,
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            config,
            metrics: SessionMetrics::default(),
        };
        
        let managed = ManagedSession {
            session: session.clone(),
            last_activity: Instant::now(),
            activity_count: 0,
        };
        
        self.sessions.insert(session.id.clone(), managed);
        
        Ok(session)
    }
    
    /// Get session
    pub fn get(&self, session_id: &str) -> Option<IsolationSession> {
        self.sessions.get(session_id).map(|m| m.session.clone())
    }
    
    /// Update session activity
    pub fn touch(&self, session_id: &str) {
        if let Some(mut managed) = self.sessions.get_mut(session_id) {
            managed.last_activity = Instant::now();
            managed.activity_count += 1;
            managed.session.last_activity = chrono::Utc::now();
        }
    }
    
    /// Update session status
    pub fn set_status(&self, session_id: &str, status: SessionStatus) {
        if let Some(mut managed) = self.sessions.get_mut(session_id) {
            managed.session.status = status;
        }
    }
    
    /// Update session metrics
    pub fn update_metrics<F>(&self, session_id: &str, f: F)
    where
        F: FnOnce(&mut SessionMetrics),
    {
        if let Some(mut managed) = self.sessions.get_mut(session_id) {
            f(&mut managed.session.metrics);
        }
    }
    
    /// Remove session
    pub fn remove(&self, session_id: &str) -> Option<IsolationSession> {
        self.sessions.remove(session_id).map(|(_, m)| m.session)
    }
    
    /// Get sessions by user
    pub fn get_by_user(&self, user_id: &str) -> Vec<IsolationSession> {
        self.sessions.iter()
            .filter(|m| m.session.user_id == user_id)
            .map(|m| m.session.clone())
            .collect()
    }
    
    /// Cleanup expired sessions
    pub fn cleanup(&self) -> Vec<String> {
        let now = Instant::now();
        let mut expired = Vec::new();
        
        self.sessions.retain(|id, managed| {
            let idle = now.duration_since(managed.last_activity);
            let total = now.duration_since(managed.last_activity);
            
            if idle > self.config.idle_timeout || total > self.config.max_session_duration {
                expired.push(id.clone());
                false
            } else {
                true
            }
        });
        
        expired
    }
    
    /// Get all active sessions
    pub fn list_active(&self) -> Vec<IsolationSession> {
        self.sessions.iter()
            .filter(|m| m.session.status == SessionStatus::Active)
            .map(|m| m.session.clone())
            .collect()
    }
    
    /// Get session count
    pub fn count(&self) -> usize {
        self.sessions.len()
    }
    
    /// Get session statistics
    pub fn stats(&self) -> SessionStats {
        let mut stats = SessionStats::default();
        
        for entry in self.sessions.iter() {
            stats.total += 1;
            match entry.session.status {
                SessionStatus::Active => stats.active += 1,
                SessionStatus::Creating | SessionStatus::Initializing => stats.initializing += 1,
                SessionStatus::Paused => stats.paused += 1,
                _ => {}
            }
            stats.total_metrics.bytes_streamed += entry.session.metrics.bytes_streamed;
            stats.total_metrics.frames_sent += entry.session.metrics.frames_sent;
        }
        
        stats
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub total: usize,
    pub active: usize,
    pub initializing: usize,
    pub paused: usize,
    pub total_metrics: SessionMetrics,
}
