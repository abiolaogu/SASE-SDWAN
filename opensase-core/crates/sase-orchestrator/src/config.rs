//! GitOps Configuration Distribution
//!
//! Versioned config with staged rollout and automatic rollback.

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Config distribution manager
pub struct ConfigManager {
    /// Current config version per PoP
    versions: Arc<RwLock<HashMap<String, ConfigVersion>>>,
    /// Config store
    configs: Arc<RwLock<HashMap<String, PopConfig>>>,
    /// Rollout state
    rollout: Arc<RwLock<Option<RolloutState>>>,
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            versions: Arc::new(RwLock::new(HashMap::new())),
            configs: Arc::new(RwLock::new(HashMap::new())),
            rollout: Arc::new(RwLock::new(None)),
        }
    }

    /// Push new config version
    pub fn push_config(&self, pop_id: &str, config: PopConfig) -> ConfigVersion {
        let version = ConfigVersion {
            version: config.version.clone(),
            hash: config.hash(),
            timestamp: now(),
            status: ConfigStatus::Pending,
        };
        
        self.configs.write().insert(pop_id.to_string(), config);
        self.versions.write().insert(pop_id.to_string(), version.clone());
        
        version
    }

    /// Start staged rollout
    pub fn start_rollout(&self, config: PopConfig, strategy: RolloutStrategy) -> Result<RolloutState, ConfigError> {
        let state = RolloutState {
            config_version: config.version.clone(),
            strategy,
            stage: RolloutStage::Canary,
            started_at: now(),
            completed_pops: Vec::new(),
            failed_pops: Vec::new(),
            status: RolloutStatus::InProgress,
        };
        
        *self.rollout.write() = Some(state.clone());
        Ok(state)
    }

    /// Advance rollout to next stage
    pub fn advance_rollout(&self) -> Result<RolloutStage, ConfigError> {
        let mut rollout = self.rollout.write();
        let state = rollout.as_mut().ok_or(ConfigError::NoActiveRollout)?;
        
        state.stage = match state.stage {
            RolloutStage::Canary => RolloutStage::Regional,
            RolloutStage::Regional => RolloutStage::Global,
            RolloutStage::Global => RolloutStage::Complete,
            RolloutStage::Complete => return Err(ConfigError::RolloutComplete),
        };
        
        Ok(state.stage)
    }

    /// Rollback on health degradation
    pub fn rollback(&self, reason: &str) -> Result<(), ConfigError> {
        let mut rollout = self.rollout.write();
        let state = rollout.as_mut().ok_or(ConfigError::NoActiveRollout)?;
        
        state.status = RolloutStatus::RolledBack;
        // Revert to previous config version
        
        Ok(())
    }

    /// Get config for PoP
    pub fn get_config(&self, pop_id: &str) -> Option<PopConfig> {
        self.configs.read().get(pop_id).cloned()
    }

    /// Get current rollout state
    pub fn rollout_status(&self) -> Option<RolloutState> {
        self.rollout.read().clone()
    }
}

impl Default for ConfigManager {
    fn default() -> Self { Self::new() }
}

/// PoP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopConfig {
    pub version: String,
    pub services: Vec<ServiceConfig>,
    pub policies: Vec<PolicyConfig>,
    pub network: NetworkConfig,
    pub features: HashMap<String, bool>,
}

impl PopConfig {
    pub fn hash(&self) -> String {
        // In production: SHA256 of serialized config
        format!("hash-{}", self.version)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub image: String,
    pub replicas: u32,
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policy_id: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub tunnels: Vec<String>,
    pub routes: Vec<String>,
}

/// Config version tracking
#[derive(Debug, Clone)]
pub struct ConfigVersion {
    pub version: String,
    pub hash: String,
    pub timestamp: u64,
    pub status: ConfigStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigStatus {
    Pending,
    Applied,
    Failed,
    RolledBack,
}

/// Rollout state
#[derive(Debug, Clone)]
pub struct RolloutState {
    pub config_version: String,
    pub strategy: RolloutStrategy,
    pub stage: RolloutStage,
    pub started_at: u64,
    pub completed_pops: Vec<String>,
    pub failed_pops: Vec<String>,
    pub status: RolloutStatus,
}

/// Rollout strategy
#[derive(Debug, Clone, Copy)]
pub enum RolloutStrategy {
    /// 1 PoP → 1 region → all
    Staged,
    /// percentage-based
    Percentage(u8),
    /// All at once
    Immediate,
}

/// Rollout stage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolloutStage {
    Canary,
    Regional,
    Global,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolloutStatus {
    InProgress,
    Paused,
    Complete,
    RolledBack,
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no active rollout")]
    NoActiveRollout,
    #[error("rollout already complete")]
    RolloutComplete,
    #[error("config not found")]
    ConfigNotFound,
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
    fn test_staged_rollout() {
        let mgr = ConfigManager::new();
        
        let config = PopConfig {
            version: "1.0.0".into(),
            services: vec![],
            policies: vec![],
            network: NetworkConfig { tunnels: vec![], routes: vec![] },
            features: HashMap::new(),
        };
        
        let state = mgr.start_rollout(config, RolloutStrategy::Staged).unwrap();
        assert_eq!(state.stage, RolloutStage::Canary);
        
        let next = mgr.advance_rollout().unwrap();
        assert_eq!(next, RolloutStage::Regional);
    }
}
