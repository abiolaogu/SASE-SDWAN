//! Client configuration

use crate::traffic::TunnelMode;
use serde::{Deserialize, Serialize};

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Controller URL
    pub controller_url: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Activation code (for initial enrollment)
    pub activation_code: Option<String>,
    /// Tunnel mode
    pub tunnel_mode: TunnelMode,
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Allow user to disconnect
    pub allow_disconnect: bool,
    /// Lockdown mode (cannot disable)
    pub lockdown_mode: bool,
    /// Offline behavior
    pub offline_behavior: OfflineBehavior,
    /// Update settings
    pub update_settings: UpdateSettings,
    /// Logging level
    pub log_level: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            controller_url: "https://controller.opensase.io".into(),
            tenant_id: String::new(),
            activation_code: None,
            tunnel_mode: TunnelMode::FullTunnel,
            auto_connect: true,
            allow_disconnect: true,
            lockdown_mode: false,
            offline_behavior: OfflineBehavior::AllowCached,
            update_settings: UpdateSettings::default(),
            log_level: "info".into(),
        }
    }
}

impl ClientConfig {
    /// Load from file
    pub fn load(path: &str) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Save to file
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, content)
    }

    /// Get config path for platform
    pub fn default_path() -> String {
        #[cfg(target_os = "windows")]
        return r"C:\ProgramData\OpenSASE\config.json".into();
        #[cfg(target_os = "macos")]
        return "/Library/Application Support/OpenSASE/config.json".into();
        #[cfg(target_os = "linux")]
        return "/etc/opensase/config.json".into();
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        return "config.json".into();
    }
}

/// Offline behavior
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OfflineBehavior {
    /// Allow all traffic when offline
    AllowAll,
    /// Allow only cached policies
    AllowCached,
    /// Block all traffic when offline
    BlockAll,
}

/// Update settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettings {
    /// Auto-update enabled
    pub auto_update: bool,
    /// Update channel
    pub channel: UpdateChannel,
    /// Pinned version (enterprise)
    pub pinned_version: Option<String>,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_update: true,
            channel: UpdateChannel::Stable,
            pinned_version: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum UpdateChannel {
    Stable,
    Beta,
    Canary,
}
