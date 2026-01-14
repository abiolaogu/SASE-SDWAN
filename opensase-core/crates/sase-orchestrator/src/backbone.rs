//! Inter-PoP Backbone Mesh
//!
//! WireGuard tunnels between all PoPs with latency-aware routing.

use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use parking_lot::RwLock;
use std::sync::Arc;

/// Backbone mesh network
pub struct BackboneMesh {
    /// PoP nodes
    nodes: Arc<RwLock<HashMap<String, BackboneNode>>>,
    /// Tunnel connections (pop_id, pop_id) → tunnel
    tunnels: Arc<RwLock<HashMap<(String, String), WireGuardTunnel>>>,
    /// Latency matrix
    latency_matrix: Arc<RwLock<HashMap<(String, String), u32>>>,
}

impl BackboneMesh {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            latency_matrix: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add PoP to backbone
    pub fn add_node(&self, node: BackboneNode) {
        let pop_id = node.pop_id.clone();
        self.nodes.write().insert(pop_id, node);
    }

    /// Create WireGuard tunnel between two PoPs
    pub fn create_tunnel(&self, pop_a: &str, pop_b: &str) -> WireGuardTunnel {
        let tunnel = WireGuardTunnel::new(pop_a, pop_b);
        
        let key = if pop_a < pop_b {
            (pop_a.to_string(), pop_b.to_string())
        } else {
            (pop_b.to_string(), pop_a.to_string())
        };
        
        self.tunnels.write().insert(key, tunnel.clone());
        tunnel
    }

    /// Update latency measurement
    pub fn update_latency(&self, pop_a: &str, pop_b: &str, latency_ms: u32) {
        let mut matrix = self.latency_matrix.write();
        matrix.insert((pop_a.to_string(), pop_b.to_string()), latency_ms);
        matrix.insert((pop_b.to_string(), pop_a.to_string()), latency_ms);
    }

    /// Get shortest path using Dijkstra
    pub fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        let nodes = self.nodes.read();
        let latency = self.latency_matrix.read();

        let mut distances: HashMap<String, u32> = HashMap::new();
        let mut previous: HashMap<String, String> = HashMap::new();
        let mut heap = BinaryHeap::new();

        for pop_id in nodes.keys() {
            distances.insert(pop_id.clone(), u32::MAX);
        }
        distances.insert(from.to_string(), 0);
        heap.push(DijkstraState { cost: 0, node: from.to_string() });

        while let Some(DijkstraState { cost, node }) = heap.pop() {
            if node == to {
                // Reconstruct path
                let mut path = vec![to.to_string()];
                let mut current = to.to_string();
                while let Some(prev) = previous.get(&current) {
                    path.push(prev.clone());
                    current = prev.clone();
                }
                path.reverse();
                return Some(path);
            }

            if cost > *distances.get(&node).unwrap_or(&u32::MAX) {
                continue;
            }

            // Check all neighbors
            for neighbor in nodes.keys() {
                if neighbor == &node { continue; }
                
                let edge_cost = latency.get(&(node.clone(), neighbor.clone()))
                    .copied()
                    .unwrap_or(1000);  // Default high cost if unmeasured

                let new_cost = cost + edge_cost;
                if new_cost < *distances.get(neighbor).unwrap_or(&u32::MAX) {
                    distances.insert(neighbor.clone(), new_cost);
                    previous.insert(neighbor.clone(), node.clone());
                    heap.push(DijkstraState { cost: new_cost, node: neighbor.clone() });
                }
            }
        }

        None
    }

    /// Get cheapest path (by cost, not latency)
    pub fn cheapest_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        // Similar to shortest_path but uses cost instead of latency
        // For now, delegate to shortest_path
        self.shortest_path(from, to)
    }

    /// Build full mesh between all PoPs
    pub fn build_full_mesh(&self) {
        let node_ids: Vec<String> = self.nodes.read().keys().cloned().collect();
        
        for i in 0..node_ids.len() {
            for j in (i+1)..node_ids.len() {
                self.create_tunnel(&node_ids[i], &node_ids[j]);
            }
        }
    }

    /// Get mesh status
    pub fn status(&self) -> MeshStatus {
        let nodes = self.nodes.read();
        let tunnels = self.tunnels.read();
        
        let active_tunnels = tunnels.values()
            .filter(|t| t.status == TunnelStatus::Active)
            .count();

        MeshStatus {
            total_nodes: nodes.len(),
            total_tunnels: tunnels.len(),
            active_tunnels,
            degraded_tunnels: tunnels.len() - active_tunnels,
        }
    }
}

impl Default for BackboneMesh {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
struct DijkstraState {
    cost: u32,
    node: String,
}

impl Eq for DijkstraState {}

impl PartialEq for DijkstraState {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}

impl Ord for DijkstraState {
    fn cmp(&self, other: &Self) -> Ordering {
        other.cost.cmp(&self.cost)  // Reverse for min-heap
    }
}

impl PartialOrd for DijkstraState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Backbone node (PoP)
#[derive(Debug, Clone)]
pub struct BackboneNode {
    pub pop_id: String,
    pub public_ip: String,
    pub wireguard_pubkey: String,
    pub listen_port: u16,
    pub allowed_cidrs: Vec<String>,
}

/// WireGuard tunnel
#[derive(Debug, Clone)]
pub struct WireGuardTunnel {
    pub pop_a: String,
    pub pop_b: String,
    pub interface_a: String,
    pub interface_b: String,
    pub psk: String,
    pub status: TunnelStatus,
    pub latency_ms: u32,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

impl WireGuardTunnel {
    pub fn new(pop_a: &str, pop_b: &str) -> Self {
        Self {
            pop_a: pop_a.to_string(),
            pop_b: pop_b.to_string(),
            interface_a: format!("wg-{}", pop_b),
            interface_b: format!("wg-{}", pop_a),
            psk: generate_psk(),
            status: TunnelStatus::Pending,
            latency_ms: 0,
            bytes_tx: 0,
            bytes_rx: 0,
        }
    }

    /// Generate WireGuard config for pop_a side
    pub fn config_for(&self, pop: &str, node: &BackboneNode, peer: &BackboneNode) -> String {
        format!(r#"[Interface]
PrivateKey = <PRIVATE_KEY>
ListenPort = {}

[Peer]
PublicKey = {}
PresharedKey = {}
AllowedIPs = {}
Endpoint = {}:{}
PersistentKeepalive = 25
"#, node.listen_port, peer.wireguard_pubkey, self.psk, 
    peer.allowed_cidrs.join(", "), peer.public_ip, peer.listen_port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Pending,
    Active,
    Degraded,
    Down,
}

#[derive(Debug)]
pub struct MeshStatus {
    pub total_nodes: usize,
    pub total_tunnels: usize,
    pub active_tunnels: usize,
    pub degraded_tunnels: usize,
}

/// Traffic class for routing
#[derive(Debug, Clone, Copy)]
pub enum TrafficClass {
    /// Control plane - always direct
    Control,
    /// User data - policy-based routing
    UserData,
    /// Bulk transfer - cheapest path
    Bulk,
}

fn generate_psk() -> String {
    // In production: use secure random
    "PSK_PLACEHOLDER_GENERATE_SECURELY".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dijkstra() {
        let mesh = BackboneMesh::new();
        
        mesh.add_node(BackboneNode {
            pop_id: "us-east".into(),
            public_ip: "1.1.1.1".into(),
            wireguard_pubkey: "key1".into(),
            listen_port: 51820,
            allowed_cidrs: vec!["10.0.0.0/24".into()],
        });
        
        mesh.add_node(BackboneNode {
            pop_id: "us-west".into(),
            public_ip: "2.2.2.2".into(),
            wireguard_pubkey: "key2".into(),
            listen_port: 51820,
            allowed_cidrs: vec!["10.0.1.0/24".into()],
        });
        
        mesh.add_node(BackboneNode {
            pop_id: "eu-west".into(),
            public_ip: "3.3.3.3".into(),
            wireguard_pubkey: "key3".into(),
            listen_port: 51820,
            allowed_cidrs: vec!["10.0.2.0/24".into()],
        });
        
        // Direct: us-east → us-west = 50ms
        mesh.update_latency("us-east", "us-west", 50);
        // Direct: us-east → eu-west = 80ms
        mesh.update_latency("us-east", "eu-west", 80);
        // Direct: us-west → eu-west = 100ms
        mesh.update_latency("us-west", "eu-west", 100);
        
        let path = mesh.shortest_path("us-east", "eu-west").unwrap();
        assert_eq!(path, vec!["us-east", "eu-west"]);  // Direct is 80ms < 50+100=150ms
    }

    #[test]
    fn test_full_mesh() {
        let mesh = BackboneMesh::new();
        
        for i in 0..4 {
            mesh.add_node(BackboneNode {
                pop_id: format!("pop-{}", i),
                public_ip: format!("10.0.0.{}", i),
                wireguard_pubkey: format!("key{}", i),
                listen_port: 51820,
                allowed_cidrs: vec![],
            });
        }
        
        mesh.build_full_mesh();
        
        let status = mesh.status();
        assert_eq!(status.total_nodes, 4);
        assert_eq!(status.total_tunnels, 6);  // n*(n-1)/2 = 4*3/2 = 6
    }
}
