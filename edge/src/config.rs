//! Edge Configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Edge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Site ID
    pub site_id: String,
    /// Site name
    pub site_name: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Controller URL
    pub controller_url: String,
    /// Activation code
    pub activation_code: Option<String>,
    /// Network interfaces
    pub interfaces: Vec<InterfaceConfig>,
    /// PoP connections
    pub pop_connections: Vec<PopConnection>,
    /// Local subnets
    pub local_subnets: Vec<String>,
    /// DNS servers
    pub dns_servers: Vec<String>,
    /// Security settings
    pub security: SecurityConfig,
    /// SD-WAN settings
    pub sdwan: SdwanConfig,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            site_id: String::new(),
            site_name: "Branch Office".into(),
            tenant_id: String::new(),
            controller_url: "https://controller.opensase.io".into(),
            activation_code: None,
            interfaces: vec![
                InterfaceConfig {
                    name: "eth0".into(),
                    role: InterfaceRole::Wan,
                    dhcp: true,
                    static_ip: None,
                    gateway: None,
                    priority: 100,
                    bandwidth_mbps: 100,
                },
                InterfaceConfig {
                    name: "eth1".into(),
                    role: InterfaceRole::Lan,
                    dhcp: false,
                    static_ip: Some("10.0.0.1/24".into()),
                    gateway: None,
                    priority: 0,
                    bandwidth_mbps: 1000,
                },
            ],
            pop_connections: vec![
                PopConnection {
                    pop_id: "pop-us-east".into(),
                    endpoint: "pop1.opensase.io:51820".into(),
                    public_key: "SERVER_PUBLIC_KEY".into(),
                    is_primary: true,
                },
            ],
            local_subnets: vec!["10.0.0.0/24".into()],
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            security: SecurityConfig::default(),
            sdwan: SdwanConfig::default(),
        }
    }
}

impl EdgeConfig {
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

    /// Get WAN interfaces
    pub fn wan_interfaces(&self) -> Vec<&InterfaceConfig> {
        self.interfaces.iter()
            .filter(|i| i.role == InterfaceRole::Wan)
            .collect()
    }

    /// Get LAN interfaces
    pub fn lan_interfaces(&self) -> Vec<&InterfaceConfig> {
        self.interfaces.iter()
            .filter(|i| i.role == InterfaceRole::Lan)
            .collect()
    }
}

/// Interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub role: InterfaceRole,
    pub dhcp: bool,
    pub static_ip: Option<String>,
    pub gateway: Option<String>,
    pub priority: u32,
    pub bandwidth_mbps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceRole {
    Wan,
    Lan,
    Dmz,
    Management,
}

/// PoP connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopConnection {
    pub pop_id: String,
    pub endpoint: String,
    pub public_key: String,
    pub is_primary: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub firewall_enabled: bool,
    pub ips_enabled: bool,
    pub ips_mode: String,
    pub url_filter_enabled: bool,
    pub dns_security_enabled: bool,
    pub blocked_categories: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            firewall_enabled: true,
            ips_enabled: true,
            ips_mode: "prevent".into(),
            url_filter_enabled: true,
            dns_security_enabled: true,
            blocked_categories: vec!["malware".into(), "phishing".into()],
        }
    }
}

/// SD-WAN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdwanConfig {
    pub path_selection: PathSelectionMode,
    pub probe_interval_ms: u32,
    pub failover_threshold_ms: u32,
    pub load_balance: bool,
}

impl Default for SdwanConfig {
    fn default() -> Self {
        Self {
            path_selection: PathSelectionMode::LowestLatency,
            probe_interval_ms: 1000,
            failover_threshold_ms: 3000,
            load_balance: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PathSelectionMode {
    LowestLatency,
    LowestLoss,
    CostOptimized,
    Manual,
}
