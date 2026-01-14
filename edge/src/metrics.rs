//! Metrics and Telemetry

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;

/// Metrics collector
pub struct MetricsCollector {
    system: Arc<RwLock<SystemMetrics>>,
    network: Arc<RwLock<Vec<InterfaceMetrics>>>,
    tunnel: Arc<RwLock<Vec<TunnelMetrics>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            system: Arc::new(RwLock::new(SystemMetrics::default())),
            network: Arc::new(RwLock::new(Vec::new())),
            tunnel: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Collect all metrics
    pub fn collect(&self) -> AllMetrics {
        AllMetrics {
            system: self.collect_system(),
            interfaces: self.network.read().clone(),
            tunnels: self.tunnel.read().clone(),
            timestamp: now(),
        }
    }

    /// Collect system metrics
    pub fn collect_system(&self) -> SystemMetrics {
        // In production: read from /proc or sysinfo crate
        SystemMetrics {
            cpu_percent: 15.5,
            memory_used_mb: 512,
            memory_total_mb: 4096,
            disk_used_gb: 8,
            disk_total_gb: 32,
            load_average: [0.5, 0.4, 0.3],
            uptime_secs: 86400,
            temperature_c: Some(45.0),
        }
    }

    /// Update interface metrics
    pub fn update_interface(&self, metrics: InterfaceMetrics) {
        let mut network = self.network.write();
        if let Some(existing) = network.iter_mut().find(|m| m.name == metrics.name) {
            *existing = metrics;
        } else {
            network.push(metrics);
        }
    }

    /// Update tunnel metrics
    pub fn update_tunnel(&self, metrics: TunnelMetrics) {
        let mut tunnels = self.tunnel.write();
        if let Some(existing) = tunnels.iter_mut().find(|m| m.pop_id == metrics.pop_id) {
            *existing = metrics;
        } else {
            tunnels.push(metrics);
        }
    }

    /// Export as Prometheus format
    pub fn prometheus(&self) -> String {
        let metrics = self.collect();
        let mut output = String::new();
        
        output.push_str(&format!("# HELP cpu_percent CPU usage\n"));
        output.push_str(&format!("cpu_percent {}\n", metrics.system.cpu_percent));
        
        output.push_str(&format!("# HELP memory_used_mb Memory usage\n"));
        output.push_str(&format!("memory_used_mb {}\n", metrics.system.memory_used_mb));
        
        for iface in &metrics.interfaces {
            output.push_str(&format!("interface_rx_bytes{{name=\"{}\"}} {}\n", 
                iface.name, iface.rx_bytes));
            output.push_str(&format!("interface_tx_bytes{{name=\"{}\"}} {}\n", 
                iface.name, iface.tx_bytes));
        }
        
        for tunnel in &metrics.tunnels {
            output.push_str(&format!("tunnel_latency_ms{{pop=\"{}\"}} {}\n", 
                tunnel.pop_id, tunnel.latency_ms));
        }
        
        output
    }
}

impl Default for MetricsCollector {
    fn default() -> Self { Self::new() }
}

/// All metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllMetrics {
    pub system: SystemMetrics,
    pub interfaces: Vec<InterfaceMetrics>,
    pub tunnels: Vec<TunnelMetrics>,
    pub timestamp: u64,
}

/// System metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_percent: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_gb: u64,
    pub disk_total_gb: u64,
    pub load_average: [f32; 3],
    pub uptime_secs: u64,
    pub temperature_c: Option<f32>,
}

/// Interface metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceMetrics {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

/// Tunnel metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub pop_id: String,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_percent: f32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
