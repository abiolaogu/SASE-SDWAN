//! Peering Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use parking_lot::RwLock;
use uuid::Uuid;

/// Peering Manager
pub struct PeeringManager {
    /// Our AS number
    pub asn: u32,
    /// Peers
    peers: Arc<RwLock<HashMap<Uuid, Peer>>>,
    /// IXP connections
    ixps: Arc<RwLock<HashMap<Uuid, IxpConnection>>>,
    /// Peering policy
    policy: Arc<RwLock<PeeringPolicy>>,
}

impl PeeringManager {
    pub fn new(asn: u32) -> Self {
        Self {
            asn,
            peers: Arc::new(RwLock::new(HashMap::new())),
            ixps: Arc::new(RwLock::new(HashMap::new())),
            policy: Arc::new(RwLock::new(PeeringPolicy::default())),
        }
    }

    /// Add peer
    pub fn add_peer(&self, peer: Peer) -> Uuid {
        let id = peer.id;
        self.peers.write().insert(id, peer);
        id
    }

    /// Get peer
    pub fn get_peer(&self, id: Uuid) -> Option<Peer> {
        self.peers.read().get(&id).cloned()
    }

    /// Get all peers
    pub fn get_peers(&self) -> Vec<Peer> {
        self.peers.read().values().cloned().collect()
    }

    /// Add IXP connection
    pub fn add_ixp(&self, ixp: IxpConnection) -> Uuid {
        let id = ixp.id;
        self.ixps.write().insert(id, ixp);
        id
    }

    /// Get IXP connections
    pub fn get_ixps(&self) -> Vec<IxpConnection> {
        self.ixps.read().values().cloned().collect()
    }

    /// Evaluate peering request
    pub fn evaluate_request(&self, request: &PeeringRequest) -> PeeringDecision {
        let policy = self.policy.read();

        // Check minimum requirements
        if request.traffic_gbps < policy.min_traffic_gbps {
            return PeeringDecision::Reject("Insufficient traffic volume".into());
        }

        if request.routes_count < policy.min_routes {
            return PeeringDecision::Reject("Insufficient routes".into());
        }

        // Check if already peering with this ASN
        if self.peers.read().values().any(|p| p.asn == request.asn) {
            return PeeringDecision::AlreadyPeering;
        }

        // Accept based on tier
        if request.is_content_provider {
            PeeringDecision::Accept { suggested_type: PeeringType::PublicIxp }
        } else if request.traffic_gbps >= policy.pni_threshold_gbps {
            PeeringDecision::Accept { suggested_type: PeeringType::PrivatePni }
        } else {
            PeeringDecision::Accept { suggested_type: PeeringType::PublicIxp }
        }
    }

    /// Calculate peering value
    pub fn calculate_peering_value(&self, peer_asn: u32) -> PeeringValue {
        // In production: analyze traffic patterns
        PeeringValue {
            asn: peer_asn,
            inbound_gbps: 10.0,
            outbound_gbps: 5.0,
            estimated_monthly_savings: 5000.0,
            latency_improvement_ms: 15,
        }
    }
}

/// Peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: Uuid,
    pub name: String,
    pub asn: u32,
    pub peering_type: PeeringType,
    pub status: PeerStatus,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
    pub traffic_in_gbps: f64,
    pub traffic_out_gbps: f64,
    pub ixp_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PeeringType {
    PublicIxp,
    PrivatePni,
    RouteServer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PeerStatus {
    Active,
    Pending,
    Down,
    Decommissioned,
}

/// IXP Connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IxpConnection {
    pub id: Uuid,
    pub name: String,
    pub location: String,
    pub port_speed_gbps: u32,
    pub port_cost_monthly: f64,
    pub our_ip: IpAddr,
    pub route_server_ip: Option<IpAddr>,
    pub peers_count: u32,
    pub status: IxpStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IxpStatus {
    Connected,
    Provisioning,
    Maintenance,
    Down,
}

/// Major IXPs
pub fn major_ixps() -> Vec<&'static str> {
    vec![
        "DE-CIX Frankfurt",
        "AMS-IX",
        "LINX London",
        "Equinix IX Ashburn",
        "Equinix IX Silicon Valley",
        "JPNAP Tokyo",
        "SIX Seattle",
        "Netnod Stockholm",
    ]
}

/// Peering policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringPolicy {
    pub min_traffic_gbps: f64,
    pub min_routes: u32,
    pub pni_threshold_gbps: f64,
    pub require_24x7_noc: bool,
    pub require_public_looking_glass: bool,
}

impl Default for PeeringPolicy {
    fn default() -> Self {
        Self {
            min_traffic_gbps: 0.1,
            min_routes: 10,
            pni_threshold_gbps: 10.0,
            require_24x7_noc: true,
            require_public_looking_glass: false,
        }
    }
}

/// Peering request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringRequest {
    pub asn: u32,
    pub name: String,
    pub traffic_gbps: f64,
    pub routes_count: u32,
    pub is_content_provider: bool,
    pub desired_locations: Vec<String>,
}

/// Peering decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeeringDecision {
    Accept { suggested_type: PeeringType },
    Reject(String),
    AlreadyPeering,
    NeedsReview,
}

/// Peering value calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringValue {
    pub asn: u32,
    pub inbound_gbps: f64,
    pub outbound_gbps: f64,
    pub estimated_monthly_savings: f64,
    pub latency_improvement_ms: u32,
}
