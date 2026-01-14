//! SD-WAN Controller

use crate::EdgeError;
use crate::network::InterfaceStats;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// SD-WAN controller
pub struct SdwanController {
    /// Path metrics per WAN link
    paths: Arc<RwLock<HashMap<String, PathMetrics>>>,
    /// Current best path
    active_path: Arc<RwLock<Option<String>>>,
    /// Running
    running: Arc<RwLock<bool>>,
}

impl SdwanController {
    pub fn new() -> Self {
        Self {
            paths: Arc::new(RwLock::new(HashMap::new())),
            active_path: Arc::new(RwLock::new(None)),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start SD-WAN controller
    pub async fn start(&self) -> Result<(), EdgeError> {
        tracing::info!("Starting SD-WAN controller");
        *self.running.write() = true;
        Ok(())
    }

    /// Stop SD-WAN controller
    pub async fn stop(&self) -> Result<(), EdgeError> {
        tracing::info!("Stopping SD-WAN controller");
        *self.running.write() = false;
        Ok(())
    }

    /// Update path metrics
    pub fn update_path(&self, interface: &str, metrics: PathMetrics) {
        self.paths.write().insert(interface.to_string(), metrics);
        self.select_best_path();
    }

    /// Get active path
    pub fn active_path(&self) -> Option<String> {
        self.active_path.read().clone()
    }

    /// Force path selection
    pub fn force_path(&self, interface: &str) {
        *self.active_path.write() = Some(interface.to_string());
    }

    fn select_best_path(&self) {
        let paths = self.paths.read();
        
        // Find path with lowest latency and loss
        let best = paths.iter()
            .filter(|(_, m)| m.available)
            .min_by(|(_, a), (_, b)| {
                let score_a = a.latency_ms as f32 + (a.loss_percent * 100.0);
                let score_b = b.latency_ms as f32 + (b.loss_percent * 100.0);
                score_a.partial_cmp(&score_b).unwrap()
            });

        if let Some((name, _)) = best {
            let current = self.active_path.read().clone();
            if current.as_ref() != Some(name) {
                tracing::info!("Switching to path: {}", name);
                *self.active_path.write() = Some(name.clone());
            }
        }
    }

    /// Get all path metrics
    pub fn all_paths(&self) -> HashMap<String, PathMetrics> {
        self.paths.read().clone()
    }

    /// Probe WAN links
    pub async fn probe(&self, targets: &[String]) -> HashMap<String, ProbeResult> {
        let mut results = HashMap::new();
        
        for target in targets {
            // In production: ICMP/TCP/HTTP probe
            results.insert(target.clone(), ProbeResult {
                target: target.clone(),
                latency_ms: 25,
                loss_percent: 0.0,
                jitter_ms: 2,
                success: true,
            });
        }
        
        results
    }
}

impl Default for SdwanController {
    fn default() -> Self { Self::new() }
}

/// Path metrics
#[derive(Debug, Clone)]
pub struct PathMetrics {
    pub interface: String,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_percent: f32,
    pub bandwidth_mbps: u32,
    pub available: bool,
    pub last_probe: u64,
}

/// Probe result
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub target: String,
    pub latency_ms: u32,
    pub loss_percent: f32,
    pub jitter_ms: u32,
    pub success: bool,
}
