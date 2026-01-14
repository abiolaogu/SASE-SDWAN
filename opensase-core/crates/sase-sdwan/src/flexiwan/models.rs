//! FlexiWAN API Models
//!
//! Data types matching FlexiWAN API responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// FlexiWAN Device
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiDevice {
    #[serde(rename = "_id")]
    pub id: String,
    pub machine_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    
    #[serde(default)]
    pub is_approved: bool,
    
    #[serde(default)]
    pub is_connected: bool,
    
    pub hostname: Option<String>,
    pub ip_list: Option<Vec<String>>,
    
    #[serde(default)]
    pub interfaces: Vec<FlexiInterface>,
    
    pub versions: Option<FlexiVersions>,
    
    pub created_at: Option<DateTime<Utc>>,
    pub last_connection: Option<DateTime<Utc>>,
}

/// Device interface
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiInterface {
    pub name: String,
    #[serde(rename = "type")]
    pub interface_type: Option<String>,
    pub ip4: Option<String>,
    pub ip4_mask: Option<String>,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
    #[serde(default)]
    pub is_assigned: bool,
    pub assigned_to: Option<String>,
}

/// Device versions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiVersions {
    pub agent: Option<String>,
    pub router: Option<String>,
    pub vpp: Option<String>,
}

/// FlexiWAN Tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiTunnel {
    #[serde(rename = "_id")]
    pub id: String,
    pub num: Option<u32>,
    pub device_a: String,
    pub device_b: String,
    pub interface_a: Option<String>,
    pub interface_b: Option<String>,
    #[serde(default)]
    pub is_active: bool,
    pub status: Option<String>,
    pub encryption_method: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

/// FlexiWAN Segment (VRF)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiSegment {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub segment_id: u32,
    pub description: Option<String>,
    pub color: Option<String>,
}

/// FlexiWAN Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiPolicy {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    #[serde(default)]
    pub enabled: bool,
    pub match_conditions: Option<FlexiMatchConditions>,
    pub action: Option<FlexiAction>,
}

/// Match conditions for policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiMatchConditions {
    pub segment: Option<String>,
    pub applications: Option<Vec<String>>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiAction {
    #[serde(rename = "type")]
    pub action_type: String,
    pub path: Option<String>,
    pub preferred_wan: Option<String>,
}

/// Device statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiDeviceStats {
    pub device_id: String,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub uptime: Option<u64>,
    #[serde(default)]
    pub interfaces: Vec<FlexiInterfaceStats>,
    pub timestamp: Option<DateTime<Utc>>,
}

/// Interface statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiInterfaceStats {
    pub name: String,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_packets: Option<u64>,
    pub tx_packets: Option<u64>,
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
}

/// Tunnel statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlexiTunnelStats {
    pub tunnel_id: String,
    pub status: String,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_percent: Option<f64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub timestamp: Option<DateTime<Utc>>,
}

// Conversion traits

impl FlexiDevice {
    /// Convert to domain Site
    pub fn to_site(&self) -> crate::site::Site {
        use crate::site::*;
        
        let status = if self.is_connected {
            SiteStatus::Online
        } else if self.is_approved {
            SiteStatus::Offline
        } else {
            SiteStatus::Pending
        };
        
        let wan_links: Vec<WanLink> = self.interfaces.iter()
            .filter(|i| i.interface_type.as_deref() == Some("WAN"))
            .enumerate()
            .map(|(idx, iface)| WanLink {
                id: format!("wan{}", idx),
                name: iface.name.clone(),
                interface: iface.name.clone(),
                link_type: WanLinkType::Internet,
                bandwidth_mbps: 100,
                ip_address: iface.ip4.clone(),
                gateway: iface.gateway.clone(),
                metric: iface.metric.unwrap_or(100),
                enabled: iface.is_assigned,
                status: LinkStatus::Unknown,
            })
            .collect();
        
        Site {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            location: Location {
                city: "Unknown".to_string(),
                country: "Unknown".to_string(),
                latitude: None,
                longitude: None,
                timezone: None,
            },
            site_type: SiteType::Branch,
            devices: vec![Device {
                id: self.id.clone(),
                name: self.name.clone(),
                serial: self.machine_id.clone(),
                model: None,
                firmware_version: self.versions.as_ref().and_then(|v| v.agent.clone()),
                status: if self.is_connected { DeviceStatus::Online } else { DeviceStatus::Offline },
                wan_links: wan_links.iter().map(|w| w.id.clone()).collect(),
                last_seen: self.last_connection,
            }],
            wan_links,
            segments: Vec::new(),
            status,
            created_at: self.created_at.unwrap_or_else(Utc::now),
            updated_at: Utc::now(),
        }
    }
}

impl FlexiTunnel {
    /// Convert to domain Tunnel
    pub fn to_tunnel(&self) -> crate::tunnel::Tunnel {
        use crate::tunnel::*;
        
        let status = match self.status.as_deref() {
            Some("up") => TunnelStatus::Up,
            Some("down") => TunnelStatus::Down,
            Some("configuring") => TunnelStatus::Configuring,
            _ => TunnelStatus::Down,
        };
        
        Tunnel {
            id: self.id.clone(),
            name: format!("{}-to-{}", self.device_a, self.device_b),
            tunnel_type: TunnelType::WireGuard,
            source: TunnelEndpoint {
                site_id: self.device_a.clone(),
                device_id: self.device_a.clone(),
                interface: self.interface_a.clone().unwrap_or_default(),
                public_ip: None,
                inner_ip: "10.210.0.1".parse().unwrap(),
                port: 51820,
            },
            destination: TunnelEndpoint {
                site_id: self.device_b.clone(),
                device_id: self.device_b.clone(),
                interface: self.interface_b.clone().unwrap_or_default(),
                public_ip: None,
                inner_ip: "10.210.0.2".parse().unwrap(),
                port: 51820,
            },
            status,
            metrics: TunnelMetrics::default(),
            mtu: 1420,
            wireguard: None,
            created_at: self.created_at.unwrap_or_else(Utc::now),
            updated_at: Utc::now(),
        }
    }
}

impl FlexiSegment {
    /// Convert to domain Segment
    pub fn to_segment(&self) -> crate::site::Segment {
        crate::site::Segment {
            id: self.segment_id,
            name: self.name.clone(),
            description: self.description.clone(),
            vlan: Some(self.segment_id as u16 * 100),
            color: self.color.clone(),
        }
    }
}
