//! OpenSASE Peering Engine (OSPE)
//!
//! IXP peering automation to achieve Cloudflare-like network proximity.
//! Direct ISP peering at major exchanges for reduced latency.

pub mod ixp;
pub mod peeringdb;
pub mod sessions;
pub mod route_policy;
pub mod rir_management;
pub mod bird_config;
pub mod monitoring;
pub mod looking_glass;
pub mod api;
pub mod manager;
pub mod rpki;

pub use ixp::*;
pub use peeringdb::*;
pub use sessions::*;
pub use route_policy::*;
pub use rir_management::*;
pub use bird_config::*;
pub use monitoring::*;
pub use looking_glass::*;
pub use api::*;
pub use manager::*;
pub use rpki::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// OpenSASE ASN
pub const OPENSASE_ASN: u32 = 65100;

/// IXP connection status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IxpConnectionStatus {
    Pending,
    Active,
    Degraded,
    Down,
}

/// BGP session state
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BgpSessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

/// Peering type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeeringType {
    /// Direct bilateral peering
    Bilateral,
    /// Via IXP route server
    RouteServer,
    /// Multilateral peering agreement
    Multilateral,
}

/// Internet Exchange Point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetExchange {
    pub id: u32,
    pub name: String,
    pub name_long: String,
    pub city: String,
    pub country: String,
    pub region: String,
    pub website: Option<String>,
    pub peering_policy: String,
    pub member_count: u32,
    pub traffic_gbps: Option<f64>,
    pub ipv4_prefix: Option<String>,
    pub ipv6_prefix: Option<String>,
}

/// IXP Port at an exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IxpPort {
    pub id: String,
    pub ixp_id: u32,
    pub ixp_name: String,
    pub pop_name: String,
    pub speed_mbps: u32,
    pub ipv4_address: Option<IpAddr>,
    pub ipv6_address: Option<IpAddr>,
    pub vlan_id: u16,
    pub status: IxpConnectionStatus,
    pub monthly_cost: f64,
}

/// Peer network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNetwork {
    pub asn: u32,
    pub name: String,
    pub aka: Option<String>,
    pub irr_as_set: Option<String>,
    pub website: Option<String>,
    pub looking_glass: Option<String>,
    pub peering_policy: PeeringPolicy,
    pub max_prefixes_v4: u32,
    pub max_prefixes_v6: u32,
    pub traffic_ratio: String,
    pub info_type: NetworkType,
}

/// Peering policy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeeringPolicy {
    Open,
    Selective,
    Restrictive,
    Required,
}

/// Network type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Isp,
    Nsp,
    Content,
    Enterprise,
    Cable,
    Edu,
    NotForProfit,
}

/// BGP peering session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringSession {
    pub id: String,
    pub ixp_port_id: String,
    pub peer_asn: u32,
    pub peer_name: String,
    pub peer_ip: IpAddr,
    pub local_ip: IpAddr,
    pub peering_type: PeeringType,
    pub state: BgpSessionState,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
    pub uptime_seconds: u64,
    pub last_state_change: i64,
}

/// Route server connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteServerConfig {
    pub ixp_id: u32,
    pub rs_address_v4: Option<IpAddr>,
    pub rs_address_v6: Option<IpAddr>,
    pub rs_asn: u32,
    pub enable_rpki: bool,
    pub enable_irr_filtering: bool,
    pub max_prefix_limit: u32,
}

/// Traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub session_id: String,
    pub timestamp: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub avg_latency_ms: f32,
}

/// Peering request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringRequest {
    pub id: String,
    pub peer_asn: u32,
    pub peer_name: String,
    pub ixp_id: u32,
    pub requested_at: i64,
    pub status: PeeringRequestStatus,
    pub contact_email: Option<String>,
}

/// Peering request status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeeringRequestStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// Peering metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringMetrics {
    pub total_ixps: usize,
    pub total_peers: usize,
    pub established_sessions: usize,
    pub prefixes_received: u32,
    pub prefixes_announced: u32,
    pub total_traffic_gbps: f64,
    pub avg_latency_reduction_percent: f32,
}

impl PeeringSession {
    /// Check if session is healthy
    pub fn is_healthy(&self) -> bool {
        self.state == BgpSessionState::Established && self.prefixes_received > 0
    }
}

impl IxpPort {
    /// Check if port is active
    pub fn is_active(&self) -> bool {
        self.status == IxpConnectionStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_healthy() {
        let session = PeeringSession {
            id: "test".to_string(),
            ixp_port_id: "port-1".to_string(),
            peer_asn: 13335,
            peer_name: "Cloudflare".to_string(),
            peer_ip: "192.0.2.1".parse().unwrap(),
            local_ip: "192.0.2.2".parse().unwrap(),
            peering_type: PeeringType::Bilateral,
            state: BgpSessionState::Established,
            prefixes_received: 1000,
            prefixes_sent: 10,
            uptime_seconds: 86400,
            last_state_change: 0,
        };
        
        assert!(session.is_healthy());
    }
}
