//! Path Selection Module
//!
//! SLA-based path optimization for SD-WAN.

use crate::tunnel::{Tunnel, TunnelMetrics, TunnelStatus};
use crate::policy::PathPreference;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// SLA thresholds for path quality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaThresholds {
    pub max_latency_ms: f64,
    pub max_jitter_ms: f64,
    pub max_loss_percent: f64,
    pub min_bandwidth_mbps: Option<f64>,
}

impl Default for SlaThresholds {
    fn default() -> Self {
        Self {
            max_latency_ms: 150.0,
            max_jitter_ms: 30.0,
            max_loss_percent: 1.0,
            min_bandwidth_mbps: None,
        }
    }
}

/// Application SLA profiles
impl SlaThresholds {
    /// Voice SLA - strict latency requirements
    pub fn voice() -> Self {
        Self {
            max_latency_ms: 100.0,
            max_jitter_ms: 20.0,
            max_loss_percent: 0.5,
            min_bandwidth_mbps: Some(0.1),
        }
    }
    
    /// Video conferencing SLA
    pub fn video() -> Self {
        Self {
            max_latency_ms: 150.0,
            max_jitter_ms: 30.0,
            max_loss_percent: 1.0,
            min_bandwidth_mbps: Some(2.0),
        }
    }
    
    /// Interactive applications
    pub fn interactive() -> Self {
        Self {
            max_latency_ms: 200.0,
            max_jitter_ms: 50.0,
            max_loss_percent: 2.0,
            min_bandwidth_mbps: None,
        }
    }
    
    /// Bulk data transfer
    pub fn bulk() -> Self {
        Self {
            max_latency_ms: 500.0,
            max_jitter_ms: 100.0,
            max_loss_percent: 5.0,
            min_bandwidth_mbps: Some(10.0),
        }
    }
}

/// Path metrics with scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    pub tunnel_id: String,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub loss_percent: f64,
    pub bandwidth_mbps: f64,
    pub score: f64,
    pub meets_sla: bool,
}

impl PathMetrics {
    /// Create from tunnel metrics
    pub fn from_tunnel(tunnel: &Tunnel, sla: &SlaThresholds) -> Self {
        let metrics = &tunnel.metrics;
        let meets_sla = Self::check_sla(metrics, sla);
        let score = Self::calculate_score(metrics, sla);
        
        Self {
            tunnel_id: tunnel.id.clone(),
            latency_ms: metrics.latency_ms,
            jitter_ms: metrics.jitter_ms,
            loss_percent: metrics.loss_percent,
            bandwidth_mbps: metrics.bandwidth_mbps,
            score,
            meets_sla,
        }
    }
    
    /// Check if metrics meet SLA
    fn check_sla(metrics: &TunnelMetrics, sla: &SlaThresholds) -> bool {
        metrics.latency_ms <= sla.max_latency_ms
            && metrics.jitter_ms <= sla.max_jitter_ms
            && metrics.loss_percent <= sla.max_loss_percent
            && sla.min_bandwidth_mbps
                .map(|min| metrics.bandwidth_mbps >= min)
                .unwrap_or(true)
    }
    
    /// Calculate path score (0-100, higher is better)
    fn calculate_score(metrics: &TunnelMetrics, sla: &SlaThresholds) -> f64 {
        // Latency score (0-40 points)
        let latency_score = if metrics.latency_ms <= sla.max_latency_ms {
            40.0 * (1.0 - metrics.latency_ms / sla.max_latency_ms)
        } else {
            0.0
        };
        
        // Jitter score (0-20 points)
        let jitter_score = if metrics.jitter_ms <= sla.max_jitter_ms {
            20.0 * (1.0 - metrics.jitter_ms / sla.max_jitter_ms)
        } else {
            0.0
        };
        
        // Loss score (0-30 points)
        let loss_score = if metrics.loss_percent <= sla.max_loss_percent {
            30.0 * (1.0 - metrics.loss_percent / sla.max_loss_percent)
        } else {
            0.0
        };
        
        // Bandwidth bonus (0-10 points)
        let bw_score = if let Some(min_bw) = sla.min_bandwidth_mbps {
            if metrics.bandwidth_mbps >= min_bw {
                10.0 * (metrics.bandwidth_mbps / min_bw).min(2.0) / 2.0
            } else {
                0.0
            }
        } else {
            5.0 // Base score if no BW requirement
        };
        
        latency_score + jitter_score + loss_score + bw_score
    }
}

/// Path selection result
#[derive(Debug, Clone)]
pub struct SelectedPath {
    pub primary: PathMetrics,
    pub backup: Option<PathMetrics>,
}

/// Path Selector
pub struct PathSelector {
    default_sla: SlaThresholds,
}

impl PathSelector {
    /// Create new path selector
    pub fn new() -> Self {
        Self {
            default_sla: SlaThresholds::default(),
        }
    }
    
    /// Create with custom default SLA
    pub fn with_sla(sla: SlaThresholds) -> Self {
        Self { default_sla: sla }
    }
    
    /// Select best path from available tunnels
    pub fn select_path(
        &self,
        tunnels: &[Tunnel],
        preference: PathPreference,
        sla: Option<&SlaThresholds>,
    ) -> Option<SelectedPath> {
        let sla = sla.unwrap_or(&self.default_sla);
        
        // Filter to healthy tunnels
        let healthy: Vec<&Tunnel> = tunnels.iter()
            .filter(|t| t.status == TunnelStatus::Up)
            .collect();
        
        if healthy.is_empty() {
            return None;
        }
        
        // Calculate metrics for all paths
        let mut paths: Vec<PathMetrics> = healthy.iter()
            .map(|t| PathMetrics::from_tunnel(t, sla))
            .collect();
        
        // Sort based on preference
        match preference {
            PathPreference::Best => {
                paths.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
            }
            PathPreference::LowLatency => {
                paths.sort_by(|a, b| a.latency_ms.partial_cmp(&b.latency_ms).unwrap());
            }
            PathPreference::HighBandwidth => {
                paths.sort_by(|a, b| b.bandwidth_mbps.partial_cmp(&a.bandwidth_mbps).unwrap());
            }
            PathPreference::LowCost => {
                // Would integrate with cost model
                paths.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
            }
            PathPreference::LoadBalance | PathPreference::Specific => {
                // Keep original order or use specific selection
            }
        }
        
        debug!(
            "Selected path: {} (score: {:.1}, latency: {:.1}ms)",
            paths[0].tunnel_id, paths[0].score, paths[0].latency_ms
        );
        
        Some(SelectedPath {
            primary: paths.remove(0),
            backup: paths.into_iter().find(|p| p.meets_sla),
        })
    }
    
    /// Select path with failover
    pub fn select_with_failover(
        &self,
        tunnels: &[Tunnel],
        current_tunnel_id: Option<&str>,
        sla: &SlaThresholds,
    ) -> Option<SelectedPath> {
        // Check if current path still meets SLA
        if let Some(current_id) = current_tunnel_id {
            if let Some(tunnel) = tunnels.iter().find(|t| t.id == current_id) {
                if tunnel.status == TunnelStatus::Up && tunnel.meets_sla(sla.max_latency_ms, sla.max_loss_percent) {
                    let primary = PathMetrics::from_tunnel(tunnel, sla);
                    let backup = tunnels.iter()
                        .filter(|t| t.id != current_id && t.status == TunnelStatus::Up)
                        .map(|t| PathMetrics::from_tunnel(t, sla))
                        .find(|p| p.meets_sla);
                    
                    return Some(SelectedPath { primary, backup });
                }
            }
        }
        
        // Current path doesn't meet SLA, select new best path
        self.select_path(tunnels, PathPreference::Best, Some(sla))
    }
    
    /// Get path health summary
    pub fn get_health_summary(&self, tunnels: &[Tunnel]) -> PathHealthSummary {
        let total = tunnels.len();
        let up = tunnels.iter().filter(|t| t.status == TunnelStatus::Up).count();
        let meeting_sla = tunnels.iter()
            .filter(|t| t.meets_sla(self.default_sla.max_latency_ms, self.default_sla.max_loss_percent))
            .count();
        
        PathHealthSummary { total, up, meeting_sla }
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Path health summary
#[derive(Debug, Clone)]
pub struct PathHealthSummary {
    pub total: usize,
    pub up: usize,
    pub meeting_sla: usize,
}
