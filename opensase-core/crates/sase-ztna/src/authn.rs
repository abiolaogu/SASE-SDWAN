//! Authentication Engine
//!
//! Primary authentication handling.

use crate::{Identity, IdentityProvider};
use std::collections::HashMap;

/// Authentication engine
pub struct AuthnEngine {
    /// Local user store
    local_users: dashmap::DashMap<String, LocalUser>,
    /// MFA engine
    mfa: crate::mfa::MfaEngine,
    /// Password policy
    password_policy: PasswordPolicy,
    /// Failed attempt tracker
    failed_attempts: dashmap::DashMap<String, FailedAttempts>,
}

struct LocalUser {
    id: String,
    email: String,
    name: String,
    password_hash: String,
    groups: Vec<String>,
    roles: Vec<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    last_login: Option<chrono::DateTime<chrono::Utc>>,
    locked: bool,
}

struct FailedAttempts {
    count: u32,
    first_attempt: chrono::DateTime<chrono::Utc>,
    last_attempt: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub max_age_days: u32,
    pub history_count: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            max_age_days: 90,
            history_count: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthnResult {
    pub success: bool,
    pub identity: Option<Identity>,
    pub requires_mfa: bool,
    pub mfa_challenge_id: Option<String>,
    pub error: Option<String>,
}

impl AuthnEngine {
    pub fn new() -> Self {
        Self {
            local_users: dashmap::DashMap::new(),
            mfa: crate::mfa::MfaEngine::new(),
            password_policy: PasswordPolicy::default(),
            failed_attempts: dashmap::DashMap::new(),
        }
    }
    
    /// Authenticate user with credentials
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> AuthnResult {
        // Check lockout
        if self.is_locked_out(username) {
            return AuthnResult {
                success: false,
                identity: None,
                requires_mfa: false,
                mfa_challenge_id: None,
                error: Some("Account locked due to too many failed attempts".to_string()),
            };
        }
        
        // Find user
        let user = match self.local_users.get(username) {
            Some(u) => u,
            None => {
                self.record_failed_attempt(username);
                return AuthnResult {
                    success: false,
                    identity: None,
                    requires_mfa: false,
                    mfa_challenge_id: None,
                    error: Some("Invalid credentials".to_string()),
                };
            }
        };
        
        // Check if account is locked
        if user.locked {
            return AuthnResult {
                success: false,
                identity: None,
                requires_mfa: false,
                mfa_challenge_id: None,
                error: Some("Account is locked".to_string()),
            };
        }
        
        // Verify password
        if !self.verify_password(password, &user.password_hash) {
            self.record_failed_attempt(username);
            return AuthnResult {
                success: false,
                identity: None,
                requires_mfa: false,
                mfa_challenge_id: None,
                error: Some("Invalid credentials".to_string()),
            };
        }
        
        // Clear failed attempts
        self.failed_attempts.remove(username);
        
        // Build identity
        let identity = Identity {
            id: user.id.clone(),
            user_id: user.id.clone(),
            email: user.email.clone(),
            name: user.name.clone(),
            groups: user.groups.clone(),
            roles: user.roles.clone(),
            attributes: HashMap::new(),
            mfa_verified: false,
            verified_at: chrono::Utc::now(),
            provider: IdentityProvider::Local,
        };
        
        // Check if MFA required
        let requires_mfa = self.mfa.is_mfa_enabled(&user.id);
        
        AuthnResult {
            success: true,
            identity: Some(identity),
            requires_mfa,
            mfa_challenge_id: None,
            error: None,
        }
    }
    
    fn verify_password(&self, password: &str, hash: &str) -> bool {
        // In production: use bcrypt/argon2
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = format!("{:x}", hasher.finalize());
        result == hash
    }
    
    fn is_locked_out(&self, username: &str) -> bool {
        if let Some(attempts) = self.failed_attempts.get(username) {
            let window = chrono::Duration::minutes(15);
            let in_window = chrono::Utc::now() - attempts.first_attempt < window;
            
            in_window && attempts.count >= 5
        } else {
            false
        }
    }
    
    fn record_failed_attempt(&self, username: &str) {
        let now = chrono::Utc::now();
        
        self.failed_attempts.entry(username.to_string())
            .and_modify(|a| {
                a.count += 1;
                a.last_attempt = now;
            })
            .or_insert(FailedAttempts {
                count: 1,
                first_attempt: now,
                last_attempt: now,
            });
    }
    
    /// Validate password against policy
    pub fn validate_password(&self, password: &str) -> Vec<String> {
        let mut errors = Vec::new();
        
        if password.len() < self.password_policy.min_length {
            errors.push(format!(
                "Password must be at least {} characters",
                self.password_policy.min_length
            ));
        }
        
        if self.password_policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            errors.push("Password must contain an uppercase letter".to_string());
        }
        
        if self.password_policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            errors.push("Password must contain a lowercase letter".to_string());
        }
        
        if self.password_policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            errors.push("Password must contain a digit".to_string());
        }
        
        if self.password_policy.require_special {
            let special = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
            if !password.chars().any(|c| special.contains(c)) {
                errors.push("Password must contain a special character".to_string());
            }
        }
        
        errors
    }
    
    /// Create local user
    pub fn create_user(
        &self,
        email: &str,
        name: &str,
        password: &str,
        groups: Vec<String>,
        roles: Vec<String>,
    ) -> Result<String, String> {
        // Validate password
        let errors = self.validate_password(password);
        if !errors.is_empty() {
            return Err(errors.join(", "));
        }
        
        // Hash password
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let password_hash = format!("{:x}", hasher.finalize());
        
        let id = uuid::Uuid::new_v4().to_string();
        
        self.local_users.insert(email.to_string(), LocalUser {
            id: id.clone(),
            email: email.to_string(),
            name: name.to_string(),
            password_hash,
            groups,
            roles,
            created_at: chrono::Utc::now(),
            last_login: None,
            locked: false,
        });
        
        Ok(id)
    }
    
    /// Get MFA engine
    pub fn mfa(&self) -> &crate::mfa::MfaEngine {
        &self.mfa
    }
}

impl Default for AuthnEngine {
    fn default() -> Self {
        Self::new()
    }
}
