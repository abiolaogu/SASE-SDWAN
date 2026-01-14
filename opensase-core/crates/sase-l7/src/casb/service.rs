//! CASB Service - Aggregates all SaaS connectors

use crate::casb::{
    AuditEvent, RiskySignin, SaaSConnector, SaaSProvider, SaaSUser, SharedFile,
    M365Connector, GoogleWorkspaceConnector,
};
use crate::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

/// CASB Service
pub struct CasbService {
    /// Connectors by provider
    connectors: HashMap<SaaSProvider, Arc<dyn SaaSConnector>>,
}

impl CasbService {
    /// Create new CASB service
    pub fn new() -> Self {
        Self {
            connectors: HashMap::new(),
        }
    }
    
    /// Add connector
    pub fn add_connector(&mut self, provider: SaaSProvider, connector: Arc<dyn SaaSConnector>) {
        info!("Adding CASB connector: {}", provider.as_str());
        self.connectors.insert(provider, connector);
    }
    
    /// Get all audit events from all providers
    pub async fn get_all_audit_logs(&self, since: DateTime<Utc>) -> Vec<(SaaSProvider, Vec<AuditEvent>)> {
        let mut results = Vec::new();
        
        for (provider, connector) in &self.connectors {
            match connector.get_audit_logs(since).await {
                Ok(events) => {
                    info!("Got {} audit events from {}", events.len(), provider.as_str());
                    results.push((*provider, events));
                }
                Err(e) => {
                    warn!("Failed to get audit logs from {}: {}", provider.as_str(), e);
                }
            }
        }
        
        results
    }
    
    /// Get all risky signins
    pub async fn get_all_risky_signins(&self) -> Vec<(SaaSProvider, Vec<RiskySignin>)> {
        let mut results = Vec::new();
        
        for (provider, connector) in &self.connectors {
            match connector.get_risky_signins().await {
                Ok(signins) => {
                    if !signins.is_empty() {
                        warn!("{} risky signins from {}", signins.len(), provider.as_str());
                    }
                    results.push((*provider, signins));
                }
                Err(e) => {
                    warn!("Failed to get risky signins from {}: {}", provider.as_str(), e);
                }
            }
        }
        
        results
    }
    
    /// Get all users across providers
    pub async fn get_all_users(&self) -> Vec<(SaaSProvider, Vec<SaaSUser>)> {
        let mut results = Vec::new();
        
        for (provider, connector) in &self.connectors {
            match connector.get_users().await {
                Ok(users) => {
                    results.push((*provider, users));
                }
                Err(e) => {
                    warn!("Failed to get users from {}: {}", provider.as_str(), e);
                }
            }
        }
        
        results
    }
    
    /// Find externally shared files
    pub async fn find_external_shares(&self) -> Vec<(SaaSProvider, SharedFile)> {
        let mut results = Vec::new();
        
        for (provider, connector) in &self.connectors {
            match connector.get_shared_files().await {
                Ok(files) => {
                    for file in files {
                        if file.external_share {
                            results.push((*provider, file));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get shared files from {}: {}", provider.as_str(), e);
                }
            }
        }
        
        results
    }
    
    /// Revoke session across provider
    pub async fn revoke_user_session(&self, provider: SaaSProvider, user_id: &str) -> Result<()> {
        if let Some(connector) = self.connectors.get(&provider) {
            connector.revoke_session(user_id).await?;
            info!("Revoked session for {} on {}", user_id, provider.as_str());
        }
        Ok(())
    }
    
    /// Block user across all providers
    pub async fn block_user_everywhere(&self, user_email: &str) {
        for (provider, connector) in &self.connectors {
            // Find user by email and block
            if let Ok(users) = connector.get_users().await {
                for user in users {
                    if user.email.eq_ignore_ascii_case(user_email) {
                        if let Err(e) = connector.block_user(&user.id).await {
                            warn!("Failed to block user {} on {}: {}", user_email, provider.as_str(), e);
                        } else {
                            info!("Blocked user {} on {}", user_email, provider.as_str());
                        }
                    }
                }
            }
        }
    }
    
    /// Get connected providers
    pub fn providers(&self) -> Vec<SaaSProvider> {
        self.connectors.keys().copied().collect()
    }
}

impl Default for CasbService {
    fn default() -> Self {
        Self::new()
    }
}
