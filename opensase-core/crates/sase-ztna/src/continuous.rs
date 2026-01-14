//! Continuous Evaluation
//!
//! Real-time session monitoring and re-evaluation.

use crate::{Session, SessionStatus, RiskSignal, RiskSignalType, RiskSeverity};
use std::sync::Arc;

/// Continuous evaluation engine
pub struct ContinuousEvaluator {
    /// Active sessions
    sessions: dashmap::DashMap<String, MonitoredSession>,
    /// Evaluation interval
    interval_secs: u64,
    /// Risk threshold for reevaluation
    risk_threshold: f64,
}

#[derive(Clone)]
struct MonitoredSession {
    session: Session,
    last_evaluation: chrono::DateTime<chrono::Utc>,
    evaluation_count: u32,
    current_risk: f64,
    signals: Vec<RiskSignal>,
}

impl ContinuousEvaluator {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            sessions: dashmap::DashMap::new(),
            interval_secs,
            risk_threshold: 50.0,
        }
    }
    
    /// Register session for monitoring
    pub async fn register_session(&self, session: &Session) {
        self.sessions.insert(session.id.clone(), MonitoredSession {
            session: session.clone(),
            last_evaluation: chrono::Utc::now(),
            evaluation_count: 0,
            current_risk: session.risk_score,
            signals: vec![],
        });
    }
    
    /// Unregister session
    pub async fn unregister_session(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }
    
    /// Run continuous evaluation loop
    pub async fn run(&self, risk_engine: Arc<crate::risk::RiskEngine>) {
        let interval = std::time::Duration::from_secs(self.interval_secs);
        
        loop {
            tokio::time::sleep(interval).await;
            
            for mut entry in self.sessions.iter_mut() {
                let monitored = entry.value_mut();
                
                // Skip if session expired
                if monitored.session.status != SessionStatus::Active {
                    continue;
                }
                
                // Check session expiration
                if chrono::Utc::now() > monitored.session.expires_at {
                    monitored.session.status = SessionStatus::Expired;
                    continue;
                }
                
                // Check for new risk signals
                let new_signals = self.check_for_signals(&monitored.session).await;
                
                if !new_signals.is_empty() {
                    monitored.signals.extend(new_signals.clone());
                    
                    // Calculate updated risk
                    let user_id = &monitored.session.identity.user_id;
                    let user_risk = risk_engine.get_user_risk(user_id);
                    
                    let signal_risk: f64 = new_signals.iter()
                        .map(|s| match s.severity {
                            RiskSeverity::Low => 5.0,
                            RiskSeverity::Medium => 15.0,
                            RiskSeverity::High => 30.0,
                            RiskSeverity::Critical => 50.0,
                        })
                        .sum();
                    
                    monitored.current_risk = (user_risk + signal_risk).min(100.0);
                    
                    // Take action if risk exceeds threshold
                    if monitored.current_risk > self.risk_threshold {
                        self.handle_high_risk(&mut monitored.session, &new_signals).await;
                    }
                }
                
                monitored.last_evaluation = chrono::Utc::now();
                monitored.evaluation_count += 1;
            }
        }
    }
    
    async fn check_for_signals(&self, session: &Session) -> Vec<RiskSignal> {
        let mut signals = Vec::new();
        
        // Check session age
        let session_age = chrono::Utc::now() - session.created_at;
        if session_age.num_hours() > 8 {
            signals.push(RiskSignal {
                signal_type: RiskSignalType::UnusualBehavior,
                severity: RiskSeverity::Low,
                description: "Long-running session".to_string(),
                detected_at: chrono::Utc::now(),
            });
        }
        
        // Check inactivity
        let inactivity = chrono::Utc::now() - session.last_activity;
        if inactivity.num_minutes() > 30 {
            signals.push(RiskSignal {
                signal_type: RiskSignalType::UnusualBehavior,
                severity: RiskSeverity::Low,
                description: "Session idle for 30+ minutes".to_string(),
                detected_at: chrono::Utc::now(),
            });
        }
        
        signals
    }
    
    async fn handle_high_risk(&self, session: &mut Session, signals: &[RiskSignal]) {
        tracing::warn!(
            "High risk detected for session {}: {:?}",
            session.id, signals
        );
        
        // Check for critical signals
        let has_critical = signals.iter()
            .any(|s| s.severity == RiskSeverity::Critical);
        
        if has_critical {
            session.status = SessionStatus::Revoked;
            tracing::warn!("Session {} revoked due to critical risk", session.id);
        } else {
            session.status = SessionStatus::Suspended;
            tracing::warn!("Session {} suspended pending reauthentication", session.id);
        }
    }
    
    /// Force reevaluation of session
    pub async fn reevaluate(&self, session_id: &str) -> Option<EvaluationResult> {
        let mut entry = self.sessions.get_mut(session_id)?;
        let monitored = entry.value_mut();
        
        let signals = self.check_for_signals(&monitored.session).await;
        monitored.signals.extend(signals.clone());
        monitored.last_evaluation = chrono::Utc::now();
        
        Some(EvaluationResult {
            session_id: session_id.to_string(),
            risk_score: monitored.current_risk,
            signals,
            action: if monitored.current_risk > self.risk_threshold {
                EvaluationAction::RequireReauth
            } else {
                EvaluationAction::Continue
            },
        })
    }
    
    /// Get session status
    pub fn get_status(&self, session_id: &str) -> Option<SessionMonitorStatus> {
        self.sessions.get(session_id).map(|m| SessionMonitorStatus {
            session_id: session_id.to_string(),
            current_risk: m.current_risk,
            last_evaluation: m.last_evaluation,
            evaluation_count: m.evaluation_count,
            signal_count: m.signals.len(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub session_id: String,
    pub risk_score: f64,
    pub signals: Vec<RiskSignal>,
    pub action: EvaluationAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationAction {
    Continue,
    RequireReauth,
    Suspend,
    Revoke,
}

#[derive(Debug, Clone)]
pub struct SessionMonitorStatus {
    pub session_id: String,
    pub current_risk: f64,
    pub last_evaluation: chrono::DateTime<chrono::Utc>,
    pub evaluation_count: u32,
    pub signal_count: usize,
}
