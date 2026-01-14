//! Access Request Flow
//!
//! Complete access request processing pipeline.

use crate::{
    Identity, Device, Resource, AccessAction, AccessContext, AccessRequest,
    AccessDecision, Decision, AccessCondition, Session,
    trust::{TrustEvaluationEngine, TrustRecommendation},
    policy::PolicyEngine,
    session::SessionManager,
    connector::{ConnectorManager, TunnelProtocol},
    activity::ActivityLogger,
};

/// Access request processor
pub struct AccessRequestProcessor {
    /// Trust evaluation engine
    trust_engine: TrustEvaluationEngine,
    /// Policy engine
    policy_engine: PolicyEngine,
    /// Session manager
    session_manager: SessionManager,
    /// Connector manager
    connector_manager: ConnectorManager,
    /// Activity logger
    activity_logger: ActivityLogger,
    /// Config
    config: ProcessorConfig,
}

#[derive(Clone)]
pub struct ProcessorConfig {
    pub enable_session_recording: bool,
    pub enable_dlp: bool,
    pub auto_create_tunnel: bool,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            enable_session_recording: true,
            enable_dlp: true,
            auto_create_tunnel: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessRequestResult {
    pub decision: AccessDecision,
    pub trust_score: f64,
    pub session: Option<Session>,
    pub tunnel_id: Option<String>,
}

impl AccessRequestProcessor {
    pub fn new(config: ProcessorConfig) -> Self {
        Self {
            trust_engine: TrustEvaluationEngine::new(),
            policy_engine: PolicyEngine::new(),
            session_manager: SessionManager::new(60),
            connector_manager: ConnectorManager::new(),
            activity_logger: ActivityLogger::new(),
            config,
        }
    }
    
    /// Process access request
    pub async fn process(&self, request: AccessRequest) -> AccessRequestResult {
        let start = std::time::Instant::now();
        
        tracing::info!(
            "Processing access request {} from user {}",
            request.id, request.identity.user_id
        );
        
        // Step 1: Trust Evaluation
        let trust_eval = self.trust_engine.evaluate(
            &request.identity,
            &request.device,
            &request.context,
        );
        
        tracing::debug!(
            "Trust evaluation: score={:.1}, recommendation={:?}",
            trust_eval.overall_score, trust_eval.recommendation
        );
        
        // Step 2: Policy Decision
        let initial_decision = match trust_eval.recommendation {
            TrustRecommendation::Deny => {
                return self.create_deny_result(&request, trust_eval.overall_score, "Trust score too low").await;
            }
            TrustRecommendation::AllowWithMfa if !request.identity.mfa_verified => {
                return AccessRequestResult {
                    decision: AccessDecision {
                        request_id: request.id,
                        decision: Decision::Challenge,
                        reasons: vec!["MFA required for this access level".to_string()],
                        conditions: vec![AccessCondition::RequireMfa],
                        session_id: None,
                        expires_at: None,
                        evaluated_at: chrono::Utc::now(),
                    },
                    trust_score: trust_eval.overall_score,
                    session: None,
                    tunnel_id: None,
                };
            }
            _ => trust_eval.recommendation,
        };
        
        // Step 3: Policy Evaluation
        let policy_decision = self.policy_engine.evaluate(&request).await;
        
        if policy_decision.decision == Decision::Deny {
            return self.create_deny_result(
                &request, 
                trust_eval.overall_score, 
                &policy_decision.reasons.join(", ")
            ).await;
        }
        
        // Step 4: Create/Update Session
        let session = self.session_manager.create_or_update(
            &request.identity,
            &request.device,
            &request.resource,
        ).await;
        
        // Step 5: Start Session Recording (if required)
        let should_record = matches!(
            initial_decision, 
            TrustRecommendation::AllowWithSessionRecord
        ) || self.config.enable_session_recording;
        
        if should_record {
            self.activity_logger.start_recording(
                &session,
                &request.resource,
                crate::activity::RecordingType::Full,
            );
        }
        
        // Step 6: Create Tunnel (if auto-create enabled)
        let tunnel_id = if self.config.auto_create_tunnel {
            match self.connector_manager.create_tunnel(
                &session,
                &request.resource,
                TunnelProtocol::Https,
            ).await {
                Ok(tunnel) => {
                    let _ = self.connector_manager.activate_tunnel(&tunnel.id).await;
                    Some(tunnel.id)
                }
                Err(e) => {
                    tracing::warn!("Failed to create tunnel: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        // Step 7: Log Access
        self.activity_logger.log_access(&session, &request.resource, &request.action);
        
        // Build conditions
        let mut conditions = policy_decision.conditions;
        if should_record {
            conditions.push(AccessCondition::SessionTimeout { minutes: 60 });
        }
        
        let elapsed = start.elapsed();
        tracing::info!(
            "Access granted for request {} in {:?}",
            request.id, elapsed
        );
        
        AccessRequestResult {
            decision: AccessDecision {
                request_id: request.id,
                decision: Decision::Allow,
                reasons: vec!["All checks passed".to_string()],
                conditions,
                session_id: Some(session.id.clone()),
                expires_at: Some(session.expires_at),
                evaluated_at: chrono::Utc::now(),
            },
            trust_score: trust_eval.overall_score,
            session: Some(session),
            tunnel_id,
        }
    }
    
    async fn create_deny_result(
        &self,
        request: &AccessRequest,
        trust_score: f64,
        reason: &str,
    ) -> AccessRequestResult {
        tracing::warn!(
            "Access denied for request {}: {}",
            request.id, reason
        );
        
        AccessRequestResult {
            decision: AccessDecision {
                request_id: request.id.clone(),
                decision: Decision::Deny,
                reasons: vec![reason.to_string()],
                conditions: vec![],
                session_id: None,
                expires_at: None,
                evaluated_at: chrono::Utc::now(),
            },
            trust_score,
            session: None,
            tunnel_id: None,
        }
    }
    
    /// Check content for DLP
    pub fn check_dlp(&self, session_id: &str, content: &str) -> bool {
        if !self.config.enable_dlp {
            return true; // Allow
        }
        
        let alerts = self.activity_logger.check_content(session_id, content);
        alerts.is_empty()
    }
    
    /// End session
    pub async fn end_session(&self, session_id: &str) {
        // Close tunnels
        self.connector_manager.close_session_tunnels(session_id).await;
        
        // Terminate session
        self.session_manager.terminate(session_id).await;
        
        tracing::info!("Session {} ended", session_id);
    }
}
