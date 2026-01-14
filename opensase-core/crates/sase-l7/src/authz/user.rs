//! User Directory - User lookup and management

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use crate::Result;

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: String,
    
    /// Email
    pub email: String,
    
    /// Display name
    pub display_name: String,
    
    /// Tenant ID
    pub tenant_id: String,
    
    /// Groups
    pub groups: Vec<String>,
    
    /// Roles
    pub roles: Vec<String>,
    
    /// Is active
    pub active: bool,
    
    /// MFA enabled
    pub mfa_enabled: bool,
    
    /// Risk level
    pub risk_level: RiskLevel,
}

/// User risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for RiskLevel {
    fn default() -> Self {
        Self::None
    }
}

/// User directory
pub struct UserDirectory {
    /// Users by ID
    users: DashMap<String, User>,
    
    /// Users by email
    users_by_email: DashMap<String, String>,
}

impl UserDirectory {
    /// Create new user directory
    pub fn new() -> Self {
        Self {
            users: DashMap::new(),
            users_by_email: DashMap::new(),
        }
    }
    
    /// Get user by ID
    pub async fn get_user(&self, id: &str) -> Result<Option<User>> {
        Ok(self.users.get(id).map(|u| u.clone()))
    }
    
    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        if let Some(id) = self.users_by_email.get(email) {
            return self.get_user(&id).await;
        }
        Ok(None)
    }
    
    /// Add or update user
    pub async fn upsert_user(&self, user: User) {
        self.users_by_email.insert(user.email.clone(), user.id.clone());
        self.users.insert(user.id.clone(), user);
    }
    
    /// Remove user
    pub async fn remove_user(&self, id: &str) {
        if let Some((_, user)) = self.users.remove(id) {
            self.users_by_email.remove(&user.email);
        }
    }
    
    /// Get all users for tenant
    pub async fn get_tenant_users(&self, tenant_id: &str) -> Vec<User> {
        self.users.iter()
            .filter(|u| u.tenant_id == tenant_id)
            .map(|u| u.clone())
            .collect()
    }
    
    /// Count users
    pub fn count(&self) -> usize {
        self.users.len()
    }
    
    /// Load sample users
    pub async fn load_samples(&self) {
        self.upsert_user(User {
            id: "user-001".to_string(),
            email: "admin@example.com".to_string(),
            display_name: "Admin User".to_string(),
            tenant_id: "tenant-001".to_string(),
            groups: vec!["admin".to_string(), "users".to_string()],
            roles: vec!["administrator".to_string()],
            active: true,
            mfa_enabled: true,
            risk_level: RiskLevel::None,
        }).await;
        
        self.upsert_user(User {
            id: "user-002".to_string(),
            email: "developer@example.com".to_string(),
            display_name: "Developer User".to_string(),
            tenant_id: "tenant-001".to_string(),
            groups: vec!["developers".to_string(), "users".to_string()],
            roles: vec!["developer".to_string()],
            active: true,
            mfa_enabled: false,
            risk_level: RiskLevel::Low,
        }).await;
        
        self.upsert_user(User {
            id: "user-003".to_string(),
            email: "guest@example.com".to_string(),
            display_name: "Guest User".to_string(),
            tenant_id: "tenant-001".to_string(),
            groups: vec!["guests".to_string()],
            roles: vec!["reader".to_string()],
            active: true,
            mfa_enabled: false,
            risk_level: RiskLevel::None,
        }).await;
    }
}

impl Default for UserDirectory {
    fn default() -> Self {
        Self::new()
    }
}
