//! Network Telemetry Collection

use std::collections::HashMap;
use std::time::Duration;
use parking_lot::RwLock;
use std::sync::Arc;
use serde::{Serialize, Deserialize};

/// Path metrics collected per 10s
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    /// Path identifier (pop_a → pop_b)
    pub path_id: String,
    /// Median latency
    pub latency_p50: Duration,
    /// 99th percentile latency
    pub latency_p99: Duration,
    /// Jitter (latency variance)
    pub jitter: Duration,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Available bandwidth in bytes/sec
    pub bandwidth_available: u64,
    /// Congestion score (0.0 - 1.0, higher = more congested)
    pub congestion_score: f64,
    /// Measurement timestamp
    pub timestamp: u64,
}

impl PathMetrics {
    /// Calculate path quality score (0-100, higher = better)
    pub fn quality_score(&self) -> f64 {
        let latency_score = 100.0 - (self.latency_p50.as_millis() as f64 / 5.0).min(100.0);
        let jitter_score = 100.0 - (self.jitter.as_millis() as f64 / 2.0).min(100.0);
        let loss_score = 100.0 * (1.0 - self.loss_rate);
        let congestion_score = 100.0 * (1.0 - self.congestion_score);
        
        (latency_score * 0.4 + jitter_score * 0.2 + loss_score * 0.3 + congestion_score * 0.1)
            .max(0.0).min(100.0)
    }

    /// Check if path is healthy
    pub fn is_healthy(&self) -> bool {
        self.loss_rate < 0.01 && self.latency_p50 < Duration::from_millis(100)
    }
}

/// Telemetry collector
pub struct TelemetryCollector {
    /// Current metrics per path
    metrics: Arc<RwLock<HashMap<String, PathMetrics>>>,
    /// Historical metrics (last N samples)
    history: Arc<RwLock<HashMap<String, Vec<PathMetrics>>>>,
    /// Configuration
    config: TelemetryConfig,
}

impl TelemetryCollector {
    /// Create new collector
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Record metrics for a path
    pub fn record(&self, metrics: PathMetrics) {
        let path_id = metrics.path_id.clone();
        
        // Update current
        self.metrics.write().insert(path_id.clone(), metrics.clone());
        
        // Add to history
        let mut history = self.history.write();
        let samples = history.entry(path_id).or_default();
        samples.push(metrics);
        
        // Prune old samples
        while samples.len() > self.config.history_size {
            samples.remove(0);
        }
    }

    /// Record from active probe result
    pub fn record_probe(&self, path_id: &str, rtt: Duration, success: bool) {
        let mut metrics = self.metrics.write();
        
        if let Some(m) = metrics.get_mut(path_id) {
            // Update with probe result
            if success {
                // Exponential moving average
                let alpha = 0.2;
                let new_p50 = Duration::from_secs_f64(
                    m.latency_p50.as_secs_f64() * (1.0 - alpha) + rtt.as_secs_f64() * alpha
                );
                m.latency_p50 = new_p50;
                
                // Update jitter
                let diff = if rtt > m.latency_p50 { rtt - m.latency_p50 } else { m.latency_p50 - rtt };
                m.jitter = Duration::from_secs_f64(
                    m.jitter.as_secs_f64() * (1.0 - alpha) + diff.as_secs_f64() * alpha
                );
            } else {
                // Increase loss rate
                m.loss_rate = (m.loss_rate * 0.9 + 0.1).min(1.0);
            }
            m.timestamp = now();
        } else {
            // First measurement
            metrics.insert(path_id.to_string(), PathMetrics {
                path_id: path_id.to_string(),
                latency_p50: rtt,
                latency_p99: rtt + Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                loss_rate: if success { 0.0 } else { 1.0 },
                bandwidth_available: 1_000_000_000,  // 1 Gbps default
                congestion_score: 0.0,
                timestamp: now(),
            });
        }
    }

    /// Get current metrics for path
    pub fn get(&self, path_id: &str) -> Option<PathMetrics> {
        self.metrics.read().get(path_id).cloned()
    }

    /// Get all current metrics
    pub fn all(&self) -> Vec<PathMetrics> {
        self.metrics.read().values().cloned().collect()
    }

    /// Get historical average for path
    pub fn average(&self, path_id: &str) -> Option<PathMetrics> {
        let history = self.history.read();
        let samples = history.get(path_id)?;
        
        if samples.is_empty() { return None; }
        
        let n = samples.len() as f64;
        let avg_p50: f64 = samples.iter().map(|s| s.latency_p50.as_secs_f64()).sum::<f64>() / n;
        let avg_p99: f64 = samples.iter().map(|s| s.latency_p99.as_secs_f64()).sum::<f64>() / n;
        let avg_jitter: f64 = samples.iter().map(|s| s.jitter.as_secs_f64()).sum::<f64>() / n;
        let avg_loss: f64 = samples.iter().map(|s| s.loss_rate).sum::<f64>() / n;
        let avg_congestion: f64 = samples.iter().map(|s| s.congestion_score).sum::<f64>() / n;
        
        Some(PathMetrics {
            path_id: path_id.to_string(),
            latency_p50: Duration::from_secs_f64(avg_p50),
            latency_p99: Duration::from_secs_f64(avg_p99),
            jitter: Duration::from_secs_f64(avg_jitter),
            loss_rate: avg_loss,
            bandwidth_available: samples.last()?.bandwidth_available,
            congestion_score: avg_congestion,
            timestamp: now(),
        })
    }

    /// Get paths sorted by quality
    pub fn ranked_paths(&self) -> Vec<(String, f64)> {
        let metrics = self.metrics.read();
        let mut paths: Vec<_> = metrics.iter()
            .map(|(id, m)| (id.clone(), m.quality_score()))
            .collect();
        paths.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        paths
    }

    /// Detect congestion on path
    pub fn detect_congestion(&self, path_id: &str) -> CongestionLevel {
        let history = self.history.read();
        let samples = match history.get(path_id) {
            Some(s) if s.len() >= 3 => s,
            _ => return CongestionLevel::Unknown,
        };

        let recent = &samples[samples.len()-3..];
        let avg_loss: f64 = recent.iter().map(|s| s.loss_rate).sum::<f64>() / 3.0;
        let avg_latency = recent.iter().map(|s| s.latency_p50.as_millis()).sum::<u128>() / 3;

        if avg_loss > 0.05 || avg_latency > 200 {
            CongestionLevel::Severe
        } else if avg_loss > 0.01 || avg_latency > 100 {
            CongestionLevel::Moderate
        } else if avg_loss > 0.001 || avg_latency > 50 {
            CongestionLevel::Light
        } else {
            CongestionLevel::None
        }
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new(TelemetryConfig::default())
    }
}

/// Telemetry configuration
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Sample interval
    pub sample_interval: Duration,
    /// History size per path
    pub history_size: usize,
    /// Stale threshold
    pub stale_threshold: Duration,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            sample_interval: Duration::from_secs(10),
            history_size: 360,  // 1 hour at 10s intervals
            stale_threshold: Duration::from_secs(60),
        }
    }
}

/// Congestion level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionLevel {
    Unknown,
    None,
    Light,
    Moderate,
    Severe,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_score() {
        let good = PathMetrics {
            path_id: "a→b".into(),
            latency_p50: Duration::from_millis(5),
            latency_p99: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            loss_rate: 0.0,
            bandwidth_available: 1_000_000_000,
            congestion_score: 0.0,
            timestamp: 0,
        };
        
        let bad = PathMetrics {
            path_id: "x→y".into(),
            latency_p50: Duration::from_millis(200),
            latency_p99: Duration::from_millis(500),
            jitter: Duration::from_millis(50),
            loss_rate: 0.05,
            bandwidth_available: 100_000_000,
            congestion_score: 0.8,
            timestamp: 0,
        };
        
        assert!(good.quality_score() > bad.quality_score());
        assert!(good.is_healthy());
        assert!(!bad.is_healthy());
    }

    #[test]
    fn test_telemetry_collection() {
        let collector = TelemetryCollector::default();
        
        collector.record_probe("us→eu", Duration::from_millis(80), true);
        collector.record_probe("us→eu", Duration::from_millis(85), true);
        collector.record_probe("us→eu", Duration::from_millis(82), true);
        
        let metrics = collector.get("us→eu").unwrap();
        assert!(metrics.latency_p50 > Duration::from_millis(50));
        assert!(metrics.latency_p50 < Duration::from_millis(100));
    }
}
