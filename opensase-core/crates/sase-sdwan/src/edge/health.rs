//! Edge Health Reporting
//!
//! Health metrics reported to flexiManage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete edge health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeHealth {
    /// Report timestamp
    pub timestamp: DateTime<Utc>,
    /// Edge name
    pub edge_name: String,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage percentage
    pub memory_usage: f64,
    /// Interface health
    pub interfaces: Vec<InterfaceHealth>,
    /// Tunnel health
    pub tunnels: Vec<TunnelHealth>,
    /// Seconds since last config update
    pub config_age_secs: u64,
}

/// Interface health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceHealth {
    /// Interface name
    pub name: String,
    /// Received bytes
    pub rx_bytes: u64,
    /// Transmitted bytes
    pub tx_bytes: u64,
    /// Received packets
    pub rx_packets: u64,
    /// Transmitted packets
    pub tx_packets: u64,
    /// Link status
    pub status: String,
}

/// Tunnel health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelHealth {
    /// Tunnel name
    pub name: String,
    /// Tunnel status (up/down)
    pub status: String,
    /// Latency in milliseconds
    pub latency_ms: f64,
    /// Jitter in milliseconds
    pub jitter_ms: f64,
    /// Packet loss percentage
    pub loss_percent: f64,
    /// Received bytes
    pub rx_bytes: u64,
    /// Transmitted bytes
    pub tx_bytes: u64,
    /// Last handshake time
    pub last_handshake: Option<DateTime<Utc>>,
}

impl EdgeHealth {
    /// Check if edge is healthy
    pub fn is_healthy(&self) -> bool {
        // Check CPU
        if self.cpu_usage > 90.0 {
            return false;
        }
        
        // Check memory
        if self.memory_usage > 95.0 {
            return false;
        }
        
        // Check at least one interface is up
        let any_interface_up = self.interfaces.iter()
            .any(|i| i.status == "up");
        
        if !any_interface_up {
            return false;
        }
        
        // Check config age (warn if > 5 minutes)
        if self.config_age_secs > 300 {
            return false;
        }
        
        true
    }
    
    /// Get health score (0-100)
    pub fn health_score(&self) -> u32 {
        let mut score = 100u32;
        
        // CPU penalty
        if self.cpu_usage > 80.0 {
            score -= ((self.cpu_usage - 80.0) * 2.0) as u32;
        }
        
        // Memory penalty
        if self.memory_usage > 80.0 {
            score -= ((self.memory_usage - 80.0) * 2.0) as u32;
        }
        
        // Interface down penalty
        let down_interfaces = self.interfaces.iter()
            .filter(|i| i.status != "up")
            .count();
        score = score.saturating_sub((down_interfaces * 10) as u32);
        
        // Tunnel health penalty
        for tunnel in &self.tunnels {
            if tunnel.status != "up" {
                score = score.saturating_sub(15);
            } else if tunnel.loss_percent > 5.0 {
                score = score.saturating_sub(10);
            } else if tunnel.latency_ms > 100.0 {
                score = score.saturating_sub(5);
            }
        }
        
        score
    }
}
