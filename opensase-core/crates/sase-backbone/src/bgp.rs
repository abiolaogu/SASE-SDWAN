//! BGP Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use parking_lot::RwLock;
use ipnetwork::IpNetwork;
use uuid::Uuid;

/// BGP Manager
pub struct BgpManager {
    /// Our AS number
    pub asn: u32,
    /// BGP sessions
    sessions: Arc<RwLock<HashMap<Uuid, BgpSession>>>,
    /// Routing table
    routes: Arc<RwLock<HashMap<IpNetwork, Vec<Path>>>>,
    /// Route decisions
    decisions: Arc<RwLock<HashMap<IpNetwork, RouteDecision>>>,
}

impl BgpManager {
    pub fn new(asn: u32) -> Self {
        Self {
            asn,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            routes: Arc::new(RwLock::new(HashMap::new())),
            decisions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add BGP session
    pub fn add_session(&self, session: BgpSession) -> Uuid {
        let id = session.id;
        self.sessions.write().insert(id, session);
        id
    }

    /// Get session status
    pub fn get_session(&self, id: Uuid) -> Option<BgpSession> {
        self.sessions.read().get(&id).cloned()
    }

    /// Get all sessions
    pub fn get_sessions(&self) -> Vec<BgpSession> {
        self.sessions.read().values().cloned().collect()
    }

    /// Add route
    pub fn add_route(&self, prefix: IpNetwork, path: Path) {
        let mut routes = self.routes.write();
        routes.entry(prefix).or_default().push(path.clone());
        drop(routes);
        self.recalculate_best_path(&prefix);
    }

    /// Select best path for destination
    pub fn select_best_path(&self, destination: &IpNetwork) -> Option<RouteDecision> {
        self.decisions.read().get(destination).cloned()
    }

    /// Recalculate best path
    fn recalculate_best_path(&self, prefix: &IpNetwork) {
        let routes = self.routes.read();
        if let Some(paths) = routes.get(prefix) {
            if let Some((selected, reason)) = self.best_path_selection(paths) {
                let decision = RouteDecision {
                    destination: *prefix,
                    paths: paths.clone(),
                    selected: selected.id,
                    selection_reason: reason,
                };
                self.decisions.write().insert(*prefix, decision);
            }
        }
    }

    /// BGP best path selection algorithm
    fn best_path_selection(&self, paths: &[Path]) -> Option<(Path, SelectionReason)> {
        if paths.is_empty() {
            return None;
        }

        // Simplified selection: prefer lowest latency, then lowest cost
        let mut best = paths[0].clone();
        let mut reason = SelectionReason::PolicyPreference;

        for path in paths.iter() {
            // Prefer lower latency
            if path.latency_ms < best.latency_ms {
                best = path.clone();
                reason = SelectionReason::LowestLatency;
            }
            // If equal latency, prefer lower cost
            else if path.latency_ms == best.latency_ms && path.cost_per_gb < best.cost_per_gb {
                best = path.clone();
                reason = SelectionReason::LowestCost;
            }
        }

        Some((best, reason))
    }

    /// Announce prefix
    pub fn announce(&self, prefix: IpNetwork, communities: Vec<Community>) {
        tracing::info!("Announcing {} with communities {:?}", prefix, communities);
        // In production: configure BIRD/FRR
    }

    /// Withdraw prefix
    pub fn withdraw(&self, prefix: IpNetwork) {
        tracing::info!("Withdrawing {}", prefix);
        self.routes.write().remove(&prefix);
        self.decisions.write().remove(&prefix);
    }
}

/// BGP Session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpSession {
    pub id: Uuid,
    pub name: String,
    pub peer_asn: u32,
    pub peer_ip: IpAddr,
    pub local_ip: IpAddr,
    pub state: SessionState,
    pub provider_type: ProviderType,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
    pub uptime_seconds: u64,
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

/// Provider type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProviderType {
    Transit,
    Peering,
    Customer,
    CloudBackbone,
}

/// BGP Path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    pub id: Uuid,
    pub nexthop: IpAddr,
    pub as_path: Vec<u32>,
    pub local_pref: u32,
    pub med: u32,
    pub origin: Origin,
    pub communities: Vec<Community>,
    /// Measured latency to nexthop
    pub latency_ms: u32,
    /// Cost per GB on this path
    pub cost_per_gb: f64,
    /// Provider type
    pub provider_type: ProviderType,
}

/// BGP Origin
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Origin {
    Igp,
    Egp,
    Incomplete,
}

/// BGP Community
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Community {
    pub asn: u32,
    pub value: u32,
}

impl Community {
    /// Blackhole community
    pub fn blackhole() -> Self {
        Self { asn: 65535, value: 666 }
    }

    /// No-export community
    pub fn no_export() -> Self {
        Self { asn: 65535, value: 65281 }
    }
}

/// Route decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    pub destination: IpNetwork,
    pub paths: Vec<Path>,
    pub selected: Uuid,
    pub selection_reason: SelectionReason,
}

/// Selection reason
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SelectionReason {
    LowestLatency,
    LowestCost,
    PolicyPreference,
    FailoverActive,
    ShortestAsPath,
    HighestLocalPref,
}
