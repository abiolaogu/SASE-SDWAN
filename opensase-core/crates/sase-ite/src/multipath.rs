//! Bandwidth Aggregation and Multi-Path

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Multi-path manager
pub struct MultiPathManager {
    /// Available paths
    paths: Vec<PathLink>,
    /// Load balancing mode
    mode: LoadBalanceMode,
    /// Path weights
    weights: HashMap<String, u32>,
    /// Round-robin counter
    rr_counter: AtomicU64,
}

impl MultiPathManager {
    pub fn new(mode: LoadBalanceMode) -> Self {
        Self {
            paths: Vec::new(),
            mode,
            weights: HashMap::new(),
            rr_counter: AtomicU64::new(0),
        }
    }

    /// Add path
    pub fn add_path(&mut self, path: PathLink) {
        let weight = (path.bandwidth_mbps / 10) as u32;  // Weight based on bandwidth
        self.weights.insert(path.id.clone(), weight.max(1));
        self.paths.push(path);
    }

    /// Select path for packet
    pub fn select_for_packet(&self, flow_id: u64) -> Option<&PathLink> {
        if self.paths.is_empty() { return None; }

        match self.mode {
            LoadBalanceMode::PerPacket => {
                // Round-robin across all paths
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                Some(&self.paths[idx % self.paths.len()])
            }
            LoadBalanceMode::PerFlow => {
                // Hash flow to consistent path
                let idx = (flow_id as usize) % self.paths.len();
                Some(&self.paths[idx])
            }
            LoadBalanceMode::Weighted => {
                // Weighted selection
                let total_weight: u32 = self.weights.values().sum();
                let point = (flow_id % total_weight as u64) as u32;
                
                let mut cumulative = 0;
                for path in &self.paths {
                    cumulative += self.weights.get(&path.id).copied().unwrap_or(1);
                    if point < cumulative {
                        return Some(path);
                    }
                }
                self.paths.first()
            }
            LoadBalanceMode::ActiveStandby => {
                // Use first active path
                self.paths.iter().find(|p| p.active)
            }
        }
    }

    /// Bond traffic across multiple paths (for MPTCP-like behavior)
    pub fn select_multiple(&self, count: usize) -> Vec<&PathLink> {
        let active: Vec<_> = self.paths.iter().filter(|p| p.active).collect();
        active.into_iter().take(count).collect()
    }

    /// Get total available bandwidth
    pub fn total_bandwidth(&self) -> u64 {
        self.paths.iter()
            .filter(|p| p.active)
            .map(|p| p.bandwidth_mbps)
            .sum()
    }
}

/// Path link
#[derive(Debug, Clone)]
pub struct PathLink {
    pub id: String,
    pub bandwidth_mbps: u64,
    pub latency_ms: u32,
    pub active: bool,
    pub link_type: LinkType,
}

/// Link type
#[derive(Debug, Clone, Copy)]
pub enum LinkType {
    Mpls,
    Internet,
    Lte,
    Satellite,
}

/// Load balancing mode
#[derive(Debug, Clone, Copy)]
pub enum LoadBalanceMode {
    /// Per-packet (for bulk, max throughput)
    PerPacket,
    /// Per-flow (for interactive, session affinity)
    PerFlow,
    /// Weighted (capacity-aware)
    Weighted,
    /// Active-standby (failover only)
    ActiveStandby,
}

/// Forward Error Correction (Reed-Solomon)
pub struct FecEncoder {
    /// Data packets before parity
    data_packets: u8,
    /// Parity packets
    parity_packets: u8,
}

impl FecEncoder {
    /// Create encoder with redundancy level
    /// e.g., new(10, 2) = 10 data + 2 parity = 20% overhead
    pub fn new(data: u8, parity: u8) -> Self {
        Self {
            data_packets: data,
            parity_packets: parity,
        }
    }

    /// Calculate overhead percentage
    pub fn overhead_percent(&self) -> f64 {
        (self.parity_packets as f64 / self.data_packets as f64) * 100.0
    }

    /// Encode block of packets
    pub fn encode(&self, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        // Simplified: just return packets + dummy parity
        // In production: use reed-solomon crate
        let mut result = packets.to_vec();
        
        for i in 0..self.parity_packets {
            let parity = self.calculate_parity(packets, i);
            result.push(parity);
        }
        
        result
    }

    /// Decode block (recover from losses)
    pub fn decode(&self, packets: &[Option<Vec<u8>>]) -> Option<Vec<Vec<u8>>> {
        let received = packets.iter().filter(|p| p.is_some()).count();
        
        // Need at least data_packets to recover
        if received < self.data_packets as usize {
            return None;
        }

        // Simplified: just return data packets
        let result: Vec<_> = packets.iter()
            .take(self.data_packets as usize)
            .filter_map(|p| p.clone())
            .collect();
        
        Some(result)
    }

    fn calculate_parity(&self, packets: &[Vec<u8>], _idx: u8) -> Vec<u8> {
        // Simplified XOR parity
        let max_len = packets.iter().map(|p| p.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; max_len];
        
        for packet in packets {
            for (i, &byte) in packet.iter().enumerate() {
                parity[i] ^= byte;
            }
        }
        
        parity
    }
}

/// Packet duplicator for critical flows
pub struct PacketDuplicator {
    /// Paths to duplicate on
    paths: Vec<String>,
}

impl PacketDuplicator {
    pub fn new(paths: Vec<String>) -> Self {
        Self { paths }
    }

    /// Get paths for duplicated transmission
    pub fn duplicate_paths(&self) -> &[String] {
        &self.paths
    }

    /// Check if flow should be duplicated
    pub fn should_duplicate(&self, dscp: u8) -> bool {
        // Only duplicate EF (voice) traffic
        dscp == 46
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_flow_lb() {
        let mut mp = MultiPathManager::new(LoadBalanceMode::PerFlow);
        
        mp.add_path(PathLink {
            id: "path1".into(),
            bandwidth_mbps: 100,
            latency_ms: 10,
            active: true,
            link_type: LinkType::Mpls,
        });
        
        mp.add_path(PathLink {
            id: "path2".into(),
            bandwidth_mbps: 50,
            latency_ms: 20,
            active: true,
            link_type: LinkType::Internet,
        });

        // Same flow should get same path
        let p1 = mp.select_for_packet(12345).unwrap().id.clone();
        let p2 = mp.select_for_packet(12345).unwrap().id.clone();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_fec() {
        let fec = FecEncoder::new(4, 1);  // 25% overhead
        
        let packets = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ];
        
        let encoded = fec.encode(&packets);
        assert_eq!(encoded.len(), 5);  // 4 data + 1 parity
    }
}
