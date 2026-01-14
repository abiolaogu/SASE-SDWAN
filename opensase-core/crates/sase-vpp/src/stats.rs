//! OpenSASE VPP Statistics Collector
//!
//! Collects real-time statistics from VPP graph nodes for monitoring
//! and observability.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Node statistics from VPP
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeStats {
    pub name: String,
    pub calls: u64,
    pub vectors: u64,
    pub suspends: u64,
    pub clocks: u64,
    pub vectors_per_call: f64,
}

/// Interface statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub name: String,
    pub sw_if_index: u32,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub drops: u64,
}

/// OpenSASE pipeline statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SasePipelineStats {
    /// Packets processed
    pub packets_processed: u64,
    
    /// Bytes processed
    pub bytes_processed: u64,
    
    /// Packets dropped
    pub packets_dropped: u64,
    
    /// Active sessions
    pub active_sessions: u64,
    
    /// Sessions created
    pub sessions_created: u64,
    
    /// Sessions expired
    pub sessions_expired: u64,
    
    /// Policy hits per action
    pub policy_hits: HashMap<String, u64>,
    
    /// DLP patterns matched
    pub dlp_patterns_matched: u64,
    
    /// DLP bytes inspected
    pub dlp_bytes_inspected: u64,
    
    /// NAT translations
    pub nat_translations: u64,
}

/// Per-worker statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkerStats {
    pub worker_id: u32,
    pub cpu_id: u32,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub packets_dropped: u64,
    pub vector_rate: f64,
    pub last_update: Option<std::time::SystemTime>,
}

/// VPP Statistics Collector
pub struct VppStatsCollector {
    /// VPP stats socket path
    stats_socket: String,
    
    /// Cached node stats
    node_stats: Arc<RwLock<HashMap<String, NodeStats>>>,
    
    /// Cached interface stats
    interface_stats: Arc<RwLock<HashMap<u32, InterfaceStats>>>,
    
    /// Cached pipeline stats
    pipeline_stats: Arc<RwLock<SasePipelineStats>>,
    
    /// Worker stats
    worker_stats: Arc<RwLock<HashMap<u32, WorkerStats>>>,
}

impl VppStatsCollector {
    /// Create new stats collector
    pub fn new(stats_socket: &str) -> Self {
        Self {
            stats_socket: stats_socket.to_string(),
            node_stats: Arc::new(RwLock::new(HashMap::new())),
            interface_stats: Arc::new(RwLock::new(HashMap::new())),
            pipeline_stats: Arc::new(RwLock::new(SasePipelineStats::default())),
            worker_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Collect all statistics
    pub async fn collect(&self) -> Result<(), String> {
        self.collect_node_stats().await?;
        self.collect_interface_stats().await?;
        self.collect_pipeline_stats().await?;
        self.collect_worker_stats().await?;
        Ok(())
    }
    
    /// Collect node statistics
    async fn collect_node_stats(&self) -> Result<(), String> {
        // TODO: Connect to VPP stats segment and read node counters
        // For now, simulate with example data
        
        let mut stats = self.node_stats.write().await;
        
        // OpenSASE nodes
        let nodes = [
            "opensase-tenant",
            "opensase-security",
            "opensase-policy",
            "opensase-dlp",
            "opensase-classify",
            "opensase-qos",
            "opensase-nat",
            "opensase-encap",
        ];
        
        for name in nodes {
            stats.insert(name.to_string(), NodeStats {
                name: name.to_string(),
                calls: 1000000,
                vectors: 256000000,
                suspends: 0,
                clocks: 500,
                vectors_per_call: 256.0,
            });
        }
        
        Ok(())
    }
    
    /// Collect interface statistics
    async fn collect_interface_stats(&self) -> Result<(), String> {
        // TODO: Connect to VPP and read interface counters
        
        let mut stats = self.interface_stats.write().await;
        
        stats.insert(0, InterfaceStats {
            name: "wan0".to_string(),
            sw_if_index: 0,
            rx_packets: 100_000_000,
            rx_bytes: 100_000_000_000,
            tx_packets: 100_000_000,
            tx_bytes: 100_000_000_000,
            rx_errors: 0,
            tx_errors: 0,
            drops: 0,
        });
        
        stats.insert(1, InterfaceStats {
            name: "lan0".to_string(),
            sw_if_index: 1,
            rx_packets: 50_000_000,
            rx_bytes: 50_000_000_000,
            tx_packets: 50_000_000,
            tx_bytes: 50_000_000_000,
            rx_errors: 0,
            tx_errors: 0,
            drops: 0,
        });
        
        Ok(())
    }
    
    /// Collect OpenSASE pipeline statistics
    async fn collect_pipeline_stats(&self) -> Result<(), String> {
        // TODO: Read from VPP opensase stats
        
        let mut stats = self.pipeline_stats.write().await;
        
        *stats = SasePipelineStats {
            packets_processed: 200_000_000,
            bytes_processed: 200_000_000_000,
            packets_dropped: 1000,
            active_sessions: 500_000,
            sessions_created: 1_000_000,
            sessions_expired: 500_000,
            policy_hits: HashMap::from([
                ("allow".to_string(), 180_000_000),
                ("deny".to_string(), 1000),
                ("inspect_dlp".to_string(), 20_000_000),
            ]),
            dlp_patterns_matched: 5000,
            dlp_bytes_inspected: 50_000_000_000,
            nat_translations: 1_000_000,
        };
        
        Ok(())
    }
    
    /// Collect worker statistics
    async fn collect_worker_stats(&self) -> Result<(), String> {
        // TODO: Read from VPP worker threads
        
        let mut stats = self.worker_stats.write().await;
        
        for i in 0..16 {
            stats.insert(i, WorkerStats {
                worker_id: i,
                cpu_id: i + 4,
                packets_processed: 12_500_000,
                bytes_processed: 12_500_000_000,
                packets_dropped: 62,
                vector_rate: 256.0,
                last_update: Some(std::time::SystemTime::now()),
            });
        }
        
        Ok(())
    }
    
    /// Get node statistics
    pub async fn get_node_stats(&self) -> HashMap<String, NodeStats> {
        self.node_stats.read().await.clone()
    }
    
    /// Get interface statistics
    pub async fn get_interface_stats(&self) -> HashMap<u32, InterfaceStats> {
        self.interface_stats.read().await.clone()
    }
    
    /// Get pipeline statistics
    pub async fn get_pipeline_stats(&self) -> SasePipelineStats {
        self.pipeline_stats.read().await.clone()
    }
    
    /// Get worker statistics
    pub async fn get_worker_stats(&self) -> HashMap<u32, WorkerStats> {
        self.worker_stats.read().await.clone()
    }
    
    /// Calculate throughput (Gbps)
    pub async fn get_throughput_gbps(&self) -> f64 {
        let interface_stats = self.interface_stats.read().await;
        
        let total_bytes: u64 = interface_stats
            .values()
            .map(|s| s.rx_bytes + s.tx_bytes)
            .sum();
        
        // Convert to Gbps (assuming 1 second collection interval)
        (total_bytes as f64 * 8.0) / 1_000_000_000.0
    }
    
    /// Calculate packets per second
    pub async fn get_pps(&self) -> u64 {
        let interface_stats = self.interface_stats.read().await;
        
        interface_stats
            .values()
            .map(|s| s.rx_packets + s.tx_packets)
            .sum()
    }
    
    /// Get average latency estimate (based on clocks per packet)
    pub async fn get_avg_latency_ns(&self) -> f64 {
        let node_stats = self.node_stats.read().await;
        
        let total_clocks: u64 = node_stats
            .values()
            .filter(|s| s.name.starts_with("opensase-"))
            .map(|s| s.clocks)
            .sum();
        
        // Assuming 3 GHz CPU, convert clocks to nanoseconds
        (total_clocks as f64) / 3.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_collect_stats() {
        let collector = VppStatsCollector::new("/run/vpp/stats.sock");
        
        collector.collect().await.unwrap();
        
        let node_stats = collector.get_node_stats().await;
        assert!(!node_stats.is_empty());
        
        let pipeline_stats = collector.get_pipeline_stats().await;
        assert!(pipeline_stats.packets_processed > 0);
    }
}
