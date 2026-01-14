//! Traffic Baseline Learning
//!
//! Adaptive baseline for zero false positive detection.

use crate::{Protocol, TrafficBaseline, TrafficSample};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Baseline learner with exponential moving average
pub struct BaselineLearner {
    /// Learning rate (0-1)
    alpha: f64,
    /// Minimum samples before baseline is valid
    min_samples: u64,
    /// Per-destination baselines
    baselines: DashMap<IpAddr, LearnedBaseline>,
}

struct LearnedBaseline {
    sample_count: AtomicU64,
    avg_pps: AtomicU64,
    avg_bps: AtomicU64,
    avg_cps: AtomicU64, // Connections per second
    protocol_counts: parking_lot::Mutex<HashMap<Protocol, u64>>,
    port_counts: parking_lot::Mutex<HashMap<u16, u64>>,
    hourly_patterns: parking_lot::Mutex<[u64; 24]>,
}

impl BaselineLearner {
    pub fn new(alpha: f64, min_samples: u64) -> Self {
        Self {
            alpha,
            min_samples,
            baselines: DashMap::new(),
        }
    }
    
    /// Update baseline with new sample
    pub fn learn(&self, sample: &TrafficSample) {
        let baseline = self.baselines
            .entry(sample.destination)
            .or_insert_with(|| LearnedBaseline::new());
        
        let count = baseline.sample_count.fetch_add(1, Ordering::Relaxed) + 1;
        
        // Exponential moving average
        let old_pps = baseline.avg_pps.load(Ordering::Relaxed) as f64;
        let new_pps = if count == 1 {
            sample.pps as f64
        } else {
            old_pps * (1.0 - self.alpha) + sample.pps as f64 * self.alpha
        };
        baseline.avg_pps.store(new_pps as u64, Ordering::Relaxed);
        
        let old_bps = baseline.avg_bps.load(Ordering::Relaxed) as f64;
        let new_bps = if count == 1 {
            sample.bps as f64
        } else {
            old_bps * (1.0 - self.alpha) + sample.bps as f64 * self.alpha
        };
        baseline.avg_bps.store(new_bps as u64, Ordering::Relaxed);
        
        // Update protocol distribution
        {
            let mut protos = baseline.protocol_counts.lock();
            *protos.entry(sample.protocol).or_default() += 1;
        }
        
        // Update port distribution
        {
            let mut ports = baseline.port_counts.lock();
            *ports.entry(sample.dst_port).or_default() += 1;
        }
        
        // Update hourly pattern
        {
            let hour = chrono::Utc::now().hour() as usize;
            let mut hourly = baseline.hourly_patterns.lock();
            hourly[hour] += sample.pps;
        }
    }
    
    /// Get baseline for destination
    pub fn get_baseline(&self, destination: &IpAddr) -> Option<TrafficBaseline> {
        self.baselines.get(destination).and_then(|b| {
            let count = b.sample_count.load(Ordering::Relaxed);
            if count < self.min_samples {
                return None;
            }
            
            let protocol_dist = {
                let protos = b.protocol_counts.lock();
                let total: u64 = protos.values().sum();
                protos.iter()
                    .map(|(k, v)| (*k, *v as f64 / total.max(1) as f64))
                    .collect()
            };
            
            let port_dist = {
                let ports = b.port_counts.lock();
                let total: u64 = ports.values().sum();
                ports.iter()
                    .map(|(k, v)| (*k, *v as f64 / total.max(1) as f64))
                    .collect()
            };
            
            Some(TrafficBaseline {
                target: *destination,
                normal_pps: b.avg_pps.load(Ordering::Relaxed),
                normal_bps: b.avg_bps.load(Ordering::Relaxed),
                normal_connections_per_sec: b.avg_cps.load(Ordering::Relaxed),
                protocol_distribution: protocol_dist,
                port_distribution: port_dist,
                geo_distribution: HashMap::new(),
                updated_at: chrono::Utc::now(),
            })
        })
    }
    
    /// Check if current traffic is anomalous
    pub fn is_anomaly(&self, destination: &IpAddr, pps: u64, bps: u64, threshold: f64) -> bool {
        if let Some(baseline) = self.get_baseline(destination) {
            baseline.is_anomaly(pps, bps, threshold)
        } else {
            // No baseline - use absolute thresholds
            pps > 100_000 || bps > 1_000_000_000
        }
    }
    
    /// Get expected traffic for current hour
    pub fn get_hourly_expected(&self, destination: &IpAddr) -> Option<u64> {
        self.baselines.get(destination).map(|b| {
            let hour = chrono::Utc::now().hour() as usize;
            let hourly = b.hourly_patterns.lock();
            let count = b.sample_count.load(Ordering::Relaxed);
            if count > 0 {
                hourly[hour] / count
            } else {
                0
            }
        })
    }
    
    /// Decay old data (call periodically)
    pub fn decay(&self, factor: f64) {
        for mut entry in self.baselines.iter_mut() {
            let baseline = entry.value_mut();
            let current = baseline.avg_pps.load(Ordering::Relaxed) as f64;
            baseline.avg_pps.store((current * factor) as u64, Ordering::Relaxed);
            
            let current = baseline.avg_bps.load(Ordering::Relaxed) as f64;
            baseline.avg_bps.store((current * factor) as u64, Ordering::Relaxed);
        }
    }
}

impl LearnedBaseline {
    fn new() -> Self {
        Self {
            sample_count: AtomicU64::new(0),
            avg_pps: AtomicU64::new(0),
            avg_bps: AtomicU64::new(0),
            avg_cps: AtomicU64::new(0),
            protocol_counts: parking_lot::Mutex::new(HashMap::new()),
            port_counts: parking_lot::Mutex::new(HashMap::new()),
            hourly_patterns: parking_lot::Mutex::new([0u64; 24]),
        }
    }
}

use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn test_baseline_learning() {
        let learner = BaselineLearner::new(0.1, 10);
        
        // Learn normal traffic
        for i in 0..20 {
            let sample = TrafficSample {
                timestamp: Instant::now(),
                source: "1.2.3.4".parse().unwrap(),
                destination: "10.0.0.1".parse().unwrap(),
                protocol: Protocol::Tcp,
                src_port: 12345,
                dst_port: 443,
                packet_size: 1500,
                tcp_flags: Some(0x10),
                pps: 10000 + (i * 100),
                bps: 100_000_000,
            };
            learner.learn(&sample);
        }
        
        let baseline = learner.get_baseline(&"10.0.0.1".parse().unwrap());
        assert!(baseline.is_some());
        
        let bl = baseline.unwrap();
        assert!(bl.normal_pps > 0);
        assert!(bl.normal_bps > 0);
    }
}
