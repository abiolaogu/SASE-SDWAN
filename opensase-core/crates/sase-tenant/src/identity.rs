//! Identity & Access Management

use crate::model::{TenantId, IdentityProvider, TenantRole, User};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;

/// Identity manager
pub struct IdentityManager {
    /// Tenant → Identity store
    stores: Arc<RwLock<HashMap<TenantId, IdentityStore>>>,
    /// Session cache
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            stores: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure identity for tenant
    pub fn configure(&self, tenant_id: TenantId, provider: IdentityProvider) {
        let store = IdentityStore {
            tenant_id,
            provider,
            users: HashMap::new(),
            groups: HashMap::new(),
        };
        self.stores.write().insert(tenant_id, store);
    }

    /// Authenticate user
    pub fn authenticate(&self, tenant_id: &TenantId, credentials: &Credentials) -> AuthResult {
        let stores = self.stores.read();
        let store = match stores.get(tenant_id) {
            Some(s) => s,
            None => return AuthResult::Failed("Tenant not found".into()),
        };

        match &store.provider {
            IdentityProvider::Local => self.auth_local(store, credentials),
            IdentityProvider::Saml { .. } => self.auth_saml(store, credentials),
            IdentityProvider::Oidc { .. } => self.auth_oidc(store, credentials),
            IdentityProvider::Ldap { .. } => self.auth_ldap(store, credentials),
        }
    }

    fn auth_local(&self, store: &IdentityStore, creds: &Credentials) -> AuthResult {
        // Simplified local auth
        if let Some(user) = store.users.get(&creds.username) {
            // In production: proper password verification
            let session = self.create_session(store.tenant_id, user);
            AuthResult::Success(session)
        } else {
            AuthResult::Failed("Invalid credentials".into())
        }
    }

    fn auth_saml(&self, store: &IdentityStore, _creds: &Credentials) -> AuthResult {
        // SAML flow would redirect to IdP
        AuthResult::Redirect(SamlRedirect {
            idp_url: "https://idp.example.com/saml".into(),
            request_id: Uuid::new_v4().to_string(),
        })
    }

    fn auth_oidc(&self, store: &IdentityStore, _creds: &Credentials) -> AuthResult {
        // OIDC flow would redirect to authorization endpoint
        AuthResult::Redirect(SamlRedirect {
            idp_url: "https://idp.example.com/authorize".into(),
            request_id: Uuid::new_v4().to_string(),
        })
    }

    fn auth_ldap(&self, _store: &IdentityStore, _creds: &Credentials) -> AuthResult {
        // LDAP bind would happen here
        AuthResult::Failed("LDAP not configured".into())
    }

    fn create_session(&self, tenant_id: TenantId, user: &User) -> Session {
        let session = Session {
            session_id: Uuid::new_v4().to_string(),
            tenant_id,
            user_id: user.user_id,
            email: user.email.clone(),
            role: user.role.clone(),
            created_at: now(),
            expires_at: now() + 3600 * 8,  // 8 hours
        };
        
        self.sessions.write().insert(session.session_id.clone(), session.clone());
        session
    }

    /// Validate session
    pub fn validate_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read();
        let session = sessions.get(session_id)?;
        
        if session.expires_at > now() {
            Some(session.clone())
        } else {
            None
        }
    }

    /// Check permission
    pub fn check_permission(&self, session: &Session, permission: &str) -> bool {
        let perms = session.role.permissions();
        
        perms.iter().any(|&p| {
            p == "*" || p == permission || 
            (p.ends_with(":*") && permission.starts_with(&p[..p.len()-1]))
        })
    }

    /// Add user to tenant
    pub fn add_user(&self, tenant_id: &TenantId, user: User) -> Result<(), IdentityError> {
        let mut stores = self.stores.write();
        let store = stores.get_mut(tenant_id)
            .ok_or(IdentityError::TenantNotFound)?;
        
        store.users.insert(user.email.clone(), user);
        Ok(())
    }

    /// Revoke session
    pub fn revoke_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }
}

impl Default for IdentityManager {
    fn default() -> Self { Self::new() }
}

/// Identity store per tenant
#[derive(Debug, Clone)]
pub struct IdentityStore {
    pub tenant_id: TenantId,
    pub provider: IdentityProvider,
    pub users: HashMap<String, User>,
    pub groups: HashMap<String, Vec<Uuid>>,
}

/// Credentials
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Authentication result
#[derive(Debug, Clone)]
pub enum AuthResult {
    Success(Session),
    Redirect(SamlRedirect),
    MfaRequired { challenge_id: String },
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct SamlRedirect {
    pub idp_url: String,
    pub request_id: String,
}

/// Session
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub email: String,
    pub role: TenantRole,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Session {
    /// Generate JWT
    pub fn to_jwt(&self) -> String {
        // Simplified - in production use proper JWT library
        format!("jwt.{}.{}", self.tenant_id, self.session_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("tenant not found")]
    TenantNotFound,
    #[error("user not found")]
    UserNotFound,
    #[error("authentication failed")]
    AuthFailed,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_auth() {
        let mgr = IdentityManager::new();
        let tenant = TenantId::new_v4();
        
        mgr.configure(tenant, IdentityProvider::Local);
        
        mgr.add_user(&tenant, User {
            user_id: Uuid::new_v4(),
            email: "admin@example.com".into(),
            role: TenantRole::SuperAdmin,
            groups: vec![],
            device_limit: 5,
        }).unwrap();

        let result = mgr.authenticate(&tenant, &Credentials {
            username: "admin@example.com".into(),
            password: "secret".into(),
        });

        assert!(matches!(result, AuthResult::Success(_)));
    }

    #[test]
    fn test_permissions() {
        let session = Session {
            session_id: "test".into(),
            tenant_id: TenantId::new_v4(),
            user_id: Uuid::new_v4(),
            email: "test@example.com".into(),
            role: TenantRole::NetworkAdmin,
            created_at: now(),
            expires_at: now() + 3600,
        };

        let mgr = IdentityManager::new();
        
        assert!(mgr.check_permission(&session, "network:read"));
        assert!(mgr.check_permission(&session, "sites:create"));
        assert!(!mgr.check_permission(&session, "security:write"));
    }
}
