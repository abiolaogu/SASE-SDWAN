//! Multi-Factor Authentication
//!
//! MFA engine supporting multiple authentication factors.

use crate::Identity;
use std::collections::HashMap;

/// MFA Engine
pub struct MfaEngine {
    /// User MFA registrations
    user_factors: dashmap::DashMap<String, Vec<MfaFactor>>,
    /// Pending challenges
    pending_challenges: dashmap::DashMap<String, MfaChallenge>,
    /// TOTP validator
    totp_validator: TotpValidator,
}

#[derive(Debug, Clone)]
pub struct MfaFactor {
    pub id: String,
    pub factor_type: MfaFactorType,
    pub name: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaFactorType {
    Totp,
    WebAuthn,
    Push,
    Sms,
    Email,
    HardwareToken,
    Biometric,
}

#[derive(Debug, Clone)]
pub struct MfaChallenge {
    pub id: String,
    pub user_id: String,
    pub factor_type: MfaFactorType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub state: ChallengeState,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeState {
    Pending,
    Completed,
    Failed,
    Expired,
}

#[derive(Debug, Clone)]
pub struct MfaVerifyResult {
    pub success: bool,
    pub factor_type: MfaFactorType,
    pub message: Option<String>,
}

impl MfaEngine {
    pub fn new() -> Self {
        Self {
            user_factors: dashmap::DashMap::new(),
            pending_challenges: dashmap::DashMap::new(),
            totp_validator: TotpValidator::new(),
        }
    }
    
    /// Check if user has MFA enabled
    pub fn is_mfa_enabled(&self, user_id: &str) -> bool {
        self.user_factors.get(user_id)
            .map(|factors| !factors.is_empty())
            .unwrap_or(false)
    }
    
    /// Get user's MFA factors
    pub fn get_factors(&self, user_id: &str) -> Vec<MfaFactor> {
        self.user_factors.get(user_id)
            .map(|factors| factors.clone())
            .unwrap_or_default()
    }
    
    /// Create MFA challenge
    pub async fn create_challenge(
        &self,
        user_id: &str,
        factor_type: MfaFactorType,
    ) -> Result<MfaChallenge, MfaError> {
        // Check if user has this factor registered
        let factors = self.user_factors.get(user_id)
            .ok_or(MfaError::NoFactorsRegistered)?;
        
        if !factors.iter().any(|f| f.factor_type == factor_type) {
            return Err(MfaError::FactorNotRegistered);
        }
        
        let challenge = MfaChallenge {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            factor_type,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            state: ChallengeState::Pending,
            metadata: HashMap::new(),
        };
        
        // Send challenge based on factor type
        match factor_type {
            MfaFactorType::Push => self.send_push_notification(user_id, &challenge).await?,
            MfaFactorType::Sms => self.send_sms_code(user_id, &challenge).await?,
            MfaFactorType::Email => self.send_email_code(user_id, &challenge).await?,
            _ => {}
        }
        
        self.pending_challenges.insert(challenge.id.clone(), challenge.clone());
        
        Ok(challenge)
    }
    
    /// Verify MFA response
    pub async fn verify(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> MfaVerifyResult {
        let mut challenge = match self.pending_challenges.get_mut(challenge_id) {
            Some(c) => c,
            None => return MfaVerifyResult {
                success: false,
                factor_type: MfaFactorType::Totp,
                message: Some("Challenge not found".to_string()),
            },
        };
        
        // Check expiration
        if chrono::Utc::now() > challenge.expires_at {
            challenge.state = ChallengeState::Expired;
            return MfaVerifyResult {
                success: false,
                factor_type: challenge.factor_type,
                message: Some("Challenge expired".to_string()),
            };
        }
        
        // Verify based on factor type
        let success = match challenge.factor_type {
            MfaFactorType::Totp => self.verify_totp(&challenge.user_id, response),
            MfaFactorType::WebAuthn => self.verify_webauthn(&challenge, response).await,
            MfaFactorType::Push => self.verify_push(&challenge, response).await,
            MfaFactorType::Sms | MfaFactorType::Email => {
                challenge.metadata.get("code") == Some(&response.to_string())
            }
            MfaFactorType::HardwareToken => self.verify_hardware_token(&challenge, response).await,
            MfaFactorType::Biometric => self.verify_biometric(&challenge, response).await,
        };
        
        challenge.state = if success {
            ChallengeState::Completed
        } else {
            ChallengeState::Failed
        };
        
        MfaVerifyResult {
            success,
            factor_type: challenge.factor_type,
            message: if success { None } else { Some("Verification failed".to_string()) },
        }
    }
    
    fn verify_totp(&self, user_id: &str, code: &str) -> bool {
        if let Some(factors) = self.user_factors.get(user_id) {
            for factor in factors.iter() {
                if factor.factor_type == MfaFactorType::Totp {
                    if let Some(secret) = factor.metadata.get("secret") {
                        return self.totp_validator.validate(secret, code);
                    }
                }
            }
        }
        false
    }
    
    async fn verify_webauthn(&self, _challenge: &MfaChallenge, _response: &str) -> bool {
        // In production: WebAuthn verification
        true
    }
    
    async fn verify_push(&self, _challenge: &MfaChallenge, _response: &str) -> bool {
        // In production: check push notification response
        true
    }
    
    async fn verify_hardware_token(&self, _challenge: &MfaChallenge, _response: &str) -> bool {
        true
    }
    
    async fn verify_biometric(&self, _challenge: &MfaChallenge, _response: &str) -> bool {
        true
    }
    
    async fn send_push_notification(&self, user_id: &str, _challenge: &MfaChallenge) -> Result<(), MfaError> {
        tracing::info!("Sending push notification to user {}", user_id);
        Ok(())
    }
    
    async fn send_sms_code(&self, user_id: &str, challenge: &MfaChallenge) -> Result<(), MfaError> {
        let code = generate_otp_code();
        tracing::info!("Sending SMS code to user {}", user_id);
        
        // Store code in challenge metadata
        if let Some(mut c) = self.pending_challenges.get_mut(&challenge.id) {
            c.metadata.insert("code".to_string(), code);
        }
        
        Ok(())
    }
    
    async fn send_email_code(&self, user_id: &str, challenge: &MfaChallenge) -> Result<(), MfaError> {
        let code = generate_otp_code();
        tracing::info!("Sending email code to user {}", user_id);
        
        if let Some(mut c) = self.pending_challenges.get_mut(&challenge.id) {
            c.metadata.insert("code".to_string(), code);
        }
        
        Ok(())
    }
    
    /// Register MFA factor
    pub fn register_factor(&self, user_id: &str, factor: MfaFactor) {
        self.user_factors.entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(factor);
    }
}

impl Default for MfaEngine {
    fn default() -> Self {
        Self::new()
    }
}

struct TotpValidator;

impl TotpValidator {
    fn new() -> Self { Self }
    
    fn validate(&self, _secret: &str, code: &str) -> bool {
        // In production: proper TOTP validation
        code.len() == 6 && code.chars().all(|c| c.is_ascii_digit())
    }
}

fn generate_otp_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

#[derive(Debug)]
pub enum MfaError {
    NoFactorsRegistered,
    FactorNotRegistered,
    ChallengeFailed,
    ChallengeExpired,
}

impl std::fmt::Display for MfaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFactorsRegistered => write!(f, "No MFA factors registered"),
            Self::FactorNotRegistered => write!(f, "Factor not registered"),
            Self::ChallengeFailed => write!(f, "Challenge failed"),
            Self::ChallengeExpired => write!(f, "Challenge expired"),
        }
    }
}

impl std::error::Error for MfaError {}
