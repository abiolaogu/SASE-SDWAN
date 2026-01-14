//! Client Configuration
//!
//! Configuration management and persistence.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Connection settings
    pub connection: ConnectionConfig,
    /// Features
    pub features: FeatureConfig,
    /// Logging
    pub logging: LogConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub url: String,
    pub tenant_id: String,
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub auto_connect: bool,
    pub auto_reconnect: bool,
    pub reconnect_delay_ms: u64,
    pub max_reconnect_attempts: u32,
    pub keepalive_interval_secs: u64,
    pub mtu: u16,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            auto_connect: false,
            auto_reconnect: true,
            reconnect_delay_ms: 1000,
            max_reconnect_attempts: 10,
            keepalive_interval_secs: 25,
            mtu: 1420,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureConfig {
    pub always_on: bool,
    pub split_tunnel: bool,
    pub dns_protection: bool,
    pub posture_check: bool,
    pub kill_switch: bool,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            always_on: true,
            split_tunnel: true,
            dns_protection: true,
            posture_check: true,
            kill_switch: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub file_enabled: bool,
    pub max_size_mb: u32,
    pub max_files: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_enabled: true,
            max_size_mb: 10,
            max_files: 5,
        }
    }
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ReadError(e.to_string()))?;
        
        let config: Config = serde_json::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        
        Ok(config)
    }
    
    pub fn save(&self, path: &PathBuf) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::WriteError(e.to_string()))?;
        }
        
        std::fs::write(path, content)
            .map_err(|e| ConfigError::WriteError(e.to_string()))?;
        
        Ok(())
    }
    
    pub fn default_path() -> PathBuf {
        let platform = crate::platform::get_platform();
        platform.config_dir().join("config.json")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                url: "https://sase.example.com".to_string(),
                tenant_id: "default".to_string(),
                api_key: None,
            },
            connection: ConnectionConfig::default(),
            features: FeatureConfig::default(),
            logging: LogConfig::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config: {0}")]
    ReadError(String),
    
    #[error("Failed to parse config: {0}")]
    ParseError(String),
    
    #[error("Failed to serialize config: {0}")]
    SerializeError(String),
    
    #[error("Failed to write config: {0}")]
    WriteError(String),
}
