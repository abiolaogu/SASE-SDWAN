//! Edge Configuration Types
//!
//! Configuration structures synced from flexiEdge.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use super::integration::{TunnelType, PolicyType};

/// Complete edge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Configuration version
    pub version: u64,
    /// Timestamp
    pub timestamp: String,
    /// Interface configurations
    pub interfaces: Vec<InterfaceConfig>,
    /// Tunnel configurations
    pub tunnels: Vec<TunnelConfig>,
    /// Route configurations
    pub routes: Vec<RouteConfig>,
    /// Policy configurations
    pub policies: Vec<PolicyConfig>,
    /// Global settings
    pub settings: EdgeSettings,
}

/// Interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Interface name (e.g., eth0, wg0)
    pub name: String,
    /// Interface role
    pub role: InterfaceRole,
    /// IP address with prefix
    pub ip_address: Option<String>,
    /// Gateway
    pub gateway: Option<IpAddr>,
    /// MTU
    pub mtu: Option<u16>,
    /// VRF ID
    pub vrf_id: Option<u32>,
    /// DHCP enabled
    pub dhcp: bool,
    /// Admin state
    pub enabled: bool,
}

/// Interface role
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceRole {
    Wan,
    Lan,
    Management,
    Loopback,
}

/// Tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Tunnel name
    pub name: String,
    /// Tunnel type
    #[serde(default)]
    pub tunnel_type: TunnelType,
    /// Local port
    #[serde(default)]
    pub local_port: u16,
    /// Local IP
    pub local_ip: Option<IpAddr>,
    /// Remote IP
    pub remote_ip: Option<IpAddr>,
    /// VNI (for VXLAN)
    pub vni: Option<u32>,
    /// Private key (for WireGuard)
    #[serde(default)]
    pub private_key: String,
    /// Peers
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

impl Default for TunnelType {
    fn default() -> Self {
        TunnelType::WireGuard
    }
}

/// WireGuard peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Public key
    pub public_key: String,
    /// Endpoint (ip:port)
    pub endpoint: String,
    /// Allowed IPs
    pub allowed_ips: Vec<String>,
    /// Keepalive interval
    #[serde(default = "default_keepalive")]
    pub keepalive: u16,
}

fn default_keepalive() -> u16 {
    25
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Destination prefix
    pub prefix: String,
    /// Next hop IP
    pub next_hop: IpAddr,
    /// Outgoing interface
    pub interface: Option<String>,
    /// VRF ID
    pub vrf_id: Option<u32>,
    /// Metric
    #[serde(default = "default_metric")]
    pub metric: u32,
}

fn default_metric() -> u32 {
    100
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy name
    pub name: String,
    /// Policy type
    pub policy_type: PolicyType,
    /// Priority
    pub priority: u32,
    /// Rules
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    /// Applied interfaces (by index)
    #[serde(default)]
    pub interfaces: Vec<u32>,
}

impl Default for PolicyType {
    fn default() -> Self {
        PolicyType::Acl
    }
}

/// Policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule ID
    pub id: u32,
    /// Action (permit, deny, etc)
    pub action: String,
    /// Source prefix
    pub source: Option<String>,
    /// Destination prefix
    pub destination: Option<String>,
    /// Protocol (TCP=6, UDP=17, etc)
    pub protocol: Option<u8>,
    /// Source port range
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    /// Destination port range
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
}

/// Edge global settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EdgeSettings {
    /// Telemetry interval seconds
    #[serde(default = "default_telemetry_interval")]
    pub telemetry_interval: u32,
    /// Health check interval seconds
    #[serde(default = "default_health_interval")]
    pub health_check_interval: u32,
    /// Enable NAT
    #[serde(default)]
    pub nat_enabled: bool,
    /// Enable firewall
    #[serde(default)]
    pub firewall_enabled: bool,
    /// Enable QoS
    #[serde(default)]
    pub qos_enabled: bool,
}

fn default_telemetry_interval() -> u32 {
    30
}

fn default_health_interval() -> u32 {
    10
}
