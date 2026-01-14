//! Inter-PoP Mesh (WireGuard tunnels)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use parking_lot::RwLock;
use uuid::Uuid;

/// PoP Mesh Manager
pub struct PopMesh {
    /// All PoPs
    pops: Arc<RwLock<HashMap<Uuid, Pop>>>,
    /// Links between PoPs
    links: Arc<RwLock<HashMap<(Uuid, Uuid), PopLink>>>,
    /// Latency measurements
    latency: Arc<RwLock<HashMap<(Uuid, Uuid), LatencyMeasurement>>>,
}

impl PopMesh {
    pub fn new() -> Self {
        Self {
            pops: Arc::new(RwLock::new(HashMap::new())),
            links: Arc::new(RwLock::new(HashMap::new())),
            latency: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add PoP to mesh
    pub fn add_pop(&self, pop: Pop) -> Uuid {
        let id = pop.id;
        self.pops.write().insert(id, pop);
        id
    }

    /// Add link between PoPs
    pub fn add_link(&self, link: PopLink) {
        let key = (link.source_pop, link.dest_pop);
        self.links.write().insert(key, link);
    }

    /// Update latency measurement
    pub fn update_latency(&self, source: Uuid, dest: Uuid, measurement: LatencyMeasurement) {
        self.latency.write().insert((source, dest), measurement);
    }

    /// Get best path between two PoPs
    pub fn get_best_path(&self, source: Uuid, dest: Uuid) -> Option<MeshPath> {
        // Direct path
        let direct = self.latency.read().get(&(source, dest)).cloned();
        
        // Check if transit through another PoP is faster
        let pops = self.pops.read();
        let latencies = self.latency.read();
        
        let mut best_path = MeshPath {
            source,
            dest,
            via: None,
            total_latency_ms: direct.as_ref().map(|d| d.latency_ms).unwrap_or(u32::MAX),
            total_loss_percent: direct.as_ref().map(|d| d.loss_percent).unwrap_or(100.0),
        };

        // Check all transit options
        for transit_id in pops.keys() {
            if *transit_id == source || *transit_id == dest {
                continue;
            }

            let to_transit = latencies.get(&(source, *transit_id));
            let from_transit = latencies.get(&(*transit_id, dest));

            if let (Some(a), Some(b)) = (to_transit, from_transit) {
                let total = a.latency_ms + b.latency_ms;
                if total < best_path.total_latency_ms {
                    best_path = MeshPath {
                        source,
                        dest,
                        via: Some(*transit_id),
                        total_latency_ms: total,
                        total_loss_percent: 1.0 - (1.0 - a.loss_percent/100.0) * (1.0 - b.loss_percent/100.0),
                    };
                }
            }
        }

        Some(best_path)
    }

    /// Get latency matrix
    pub fn get_latency_matrix(&self) -> LatencyMatrix {
        let pops: Vec<_> = self.pops.read().keys().cloned().collect();
        let mut matrix = HashMap::new();

        for &source in &pops {
            for &dest in &pops {
                if source != dest {
                    if let Some(m) = self.latency.read().get(&(source, dest)) {
                        matrix.insert((source, dest), m.latency_ms);
                    }
                }
            }
        }

        LatencyMatrix { pops, matrix }
    }

    /// Run continuous latency probing
    pub async fn probe_all(&self) {
        let pops: Vec<_> = self.pops.read().values().cloned().collect();
        
        for source in &pops {
            for dest in &pops {
                if source.id != dest.id {
                    // In production: actual ICMP/UDP probe
                    let measurement = LatencyMeasurement {
                        latency_ms: 10 + (rand::random::<u32>() % 50),
                        jitter_ms: rand::random::<u32>() % 5,
                        loss_percent: (rand::random::<f32>() * 0.5).min(5.0),
                        measured_at: chrono::Utc::now(),
                    };
                    self.update_latency(source.id, dest.id, measurement);
                }
            }
        }
    }
}

impl Default for PopMesh {
    fn default() -> Self { Self::new() }
}

/// PoP definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pop {
    pub id: Uuid,
    pub name: String,
    pub region: String,
    pub city: String,
    pub datacenter: String,
    pub public_ip: IpAddr,
    pub wireguard_pubkey: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// Link between PoPs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopLink {
    pub id: Uuid,
    pub source_pop: Uuid,
    pub dest_pop: Uuid,
    pub tunnel_type: TunnelType,
    pub status: LinkStatus,
    pub interface: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TunnelType {
    WireGuard,
    IPsec,
    GRE,
    CloudBackbone,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LinkStatus {
    Up,
    Down,
    Degraded,
}

/// Latency measurement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyMeasurement {
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_percent: f32,
    pub measured_at: chrono::DateTime<chrono::Utc>,
}

/// Mesh path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPath {
    pub source: Uuid,
    pub dest: Uuid,
    pub via: Option<Uuid>,
    pub total_latency_ms: u32,
    pub total_loss_percent: f32,
}

/// Latency matrix
#[derive(Debug, Clone)]
pub struct LatencyMatrix {
    pub pops: Vec<Uuid>,
    pub matrix: HashMap<(Uuid, Uuid), u32>,
}
