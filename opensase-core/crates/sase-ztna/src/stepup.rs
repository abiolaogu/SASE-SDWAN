//! Step-Up Authentication
//!
//! Mid-session authentication step-up for sensitive operations.

use crate::{Session, mfa::{MfaFactorType, MfaChallenge}};

/// Step-up authentication manager
pub struct StepUpManager {
    challenges: dashmap::DashMap<String, StepUpChallenge>,
    pending_sessions: dashmap::DashMap<String, String>, // session_id -> challenge_id
}

#[derive(Clone)]
pub struct StepUpChallenge {
    pub id: String,
    pub session_id: String,
    pub user_id: String,
    pub reason: StepUpReason,
    pub challenge_type: ChallengeType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub status: ChallengeStatus,
    pub attempts: u32,
    pub max_attempts: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StepUpReason {
    SensitiveResource,
    TrustDegradation,
    HighRiskAction,
    SessionTimeout,
    PolicyRequired,
    AdminForced,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Mfa,
    Biometric,
    ReAuth,
    ManagerApproval,
    Custom,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

impl StepUpManager {
    pub fn new() -> Self {
        Self {
            challenges: dashmap::DashMap::new(),
            pending_sessions: dashmap::DashMap::new(),
        }
    }
    
    /// Create step-up challenge for session
    pub async fn create_challenge(
        &self,
        session: &Session,
        reason: StepUpReason,
    ) -> StepUpChallenge {
        // Determine challenge type based on reason
        let challenge_type = match reason {
            StepUpReason::SensitiveResource => ChallengeType::Mfa,
            StepUpReason::TrustDegradation => ChallengeType::Mfa,
            StepUpReason::HighRiskAction => ChallengeType::Biometric,
            StepUpReason::SessionTimeout => ChallengeType::ReAuth,
            StepUpReason::PolicyRequired => ChallengeType::Mfa,
            StepUpReason::AdminForced => ChallengeType::ReAuth,
        };
        
        let challenge = StepUpChallenge {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            user_id: session.identity.user_id.clone(),
            reason,
            challenge_type,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            status: ChallengeStatus::Pending,
            attempts: 0,
            max_attempts: 3,
        };
        
        // Store challenge
        self.challenges.insert(challenge.id.clone(), challenge.clone());
        self.pending_sessions.insert(session.id.clone(), challenge.id.clone());
        
        tracing::info!(
            "Created step-up challenge {} for session {} (reason: {:?})",
            challenge.id, session.id, reason
        );
        
        challenge
    }
    
    /// Check if session has pending challenge
    pub fn has_pending_challenge(&self, session_id: &str) -> bool {
        self.pending_sessions.contains_key(session_id)
    }
    
    /// Get pending challenge for session
    pub fn get_pending_challenge(&self, session_id: &str) -> Option<StepUpChallenge> {
        let challenge_id = self.pending_sessions.get(session_id)?;
        self.challenges.get(&*challenge_id).map(|c| c.clone())
    }
    
    /// Verify step-up challenge
    pub async fn verify(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> Result<StepUpResult, StepUpError> {
        let mut challenge = self.challenges.get_mut(challenge_id)
            .ok_or(StepUpError::ChallengeNotFound)?;
        
        // Check expiration
        if chrono::Utc::now() > challenge.expires_at {
            challenge.status = ChallengeStatus::Expired;
            return Err(StepUpError::Expired);
        }
        
        // Check attempts
        challenge.attempts += 1;
        if challenge.attempts > challenge.max_attempts {
            challenge.status = ChallengeStatus::Failed;
            return Err(StepUpError::TooManyAttempts);
        }
        
        // Verify based on challenge type
        let verified = match challenge.challenge_type {
            ChallengeType::Mfa => self.verify_mfa(response).await,
            ChallengeType::Biometric => self.verify_biometric(response).await,
            ChallengeType::ReAuth => self.verify_reauth(response).await,
            ChallengeType::ManagerApproval => self.verify_approval(response).await,
            ChallengeType::Custom => true,
        };
        
        if verified {
            challenge.status = ChallengeStatus::Completed;
            self.pending_sessions.remove(&challenge.session_id);
            
            tracing::info!(
                "Step-up challenge {} completed for session {}",
                challenge_id, challenge.session_id
            );
            
            Ok(StepUpResult {
                challenge_id: challenge_id.to_string(),
                session_id: challenge.session_id.clone(),
                verified: true,
                trust_bonus: self.calculate_trust_bonus(&challenge),
            })
        } else {
            if challenge.attempts >= challenge.max_attempts {
                challenge.status = ChallengeStatus::Failed;
            }
            Err(StepUpError::VerificationFailed)
        }
    }
    
    async fn verify_mfa(&self, response: &str) -> bool {
        // In production: verify TOTP/WebAuthn/etc
        !response.is_empty()
    }
    
    async fn verify_biometric(&self, response: &str) -> bool {
        // In production: verify biometric data
        !response.is_empty()
    }
    
    async fn verify_reauth(&self, response: &str) -> bool {
        // In production: verify password
        !response.is_empty()
    }
    
    async fn verify_approval(&self, response: &str) -> bool {
        // In production: check manager approval
        response == "approved"
    }
    
    fn calculate_trust_bonus(&self, challenge: &StepUpChallenge) -> f64 {
        match challenge.challenge_type {
            ChallengeType::Biometric => 15.0,
            ChallengeType::Mfa => 10.0,
            ChallengeType::ReAuth => 20.0,
            ChallengeType::ManagerApproval => 5.0,
            ChallengeType::Custom => 5.0,
        }
    }
    
    /// Cancel challenge
    pub fn cancel(&self, challenge_id: &str) {
        if let Some(mut challenge) = self.challenges.get_mut(challenge_id) {
            challenge.status = ChallengeStatus::Cancelled;
            self.pending_sessions.remove(&challenge.session_id);
        }
    }
    
    /// Cleanup expired challenges
    pub async fn cleanup_expired(&self) -> usize {
        let now = chrono::Utc::now();
        let mut removed = 0;
        
        let expired: Vec<String> = self.challenges.iter()
            .filter(|c| now > c.expires_at && c.status == ChallengeStatus::Pending)
            .map(|c| c.id.clone())
            .collect();
        
        for id in expired {
            if let Some(mut challenge) = self.challenges.get_mut(&id) {
                challenge.status = ChallengeStatus::Expired;
                self.pending_sessions.remove(&challenge.session_id);
                removed += 1;
            }
        }
        
        removed
    }
}

impl Default for StepUpManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StepUpResult {
    pub challenge_id: String,
    pub session_id: String,
    pub verified: bool,
    pub trust_bonus: f64,
}

#[derive(Debug)]
pub enum StepUpError {
    ChallengeNotFound,
    Expired,
    TooManyAttempts,
    VerificationFailed,
    AlreadyCompleted,
}

impl std::fmt::Display for StepUpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeNotFound => write!(f, "Challenge not found"),
            Self::Expired => write!(f, "Challenge expired"),
            Self::TooManyAttempts => write!(f, "Too many attempts"),
            Self::VerificationFailed => write!(f, "Verification failed"),
            Self::AlreadyCompleted => write!(f, "Already completed"),
        }
    }
}

impl std::error::Error for StepUpError {}
