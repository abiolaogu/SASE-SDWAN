//! Probe result collection and aggregation

use crate::WanLink;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Probe result from network measurement
#[derive(Debug, Clone, Copy)]
pub struct ProbeResult {
    /// Round-trip latency in microseconds
    pub latency_us: u32,
    /// Jitter (variation) in microseconds
    pub jitter_us: u32,
    /// Packet loss percentage (0-10000 for 0.00%-100.00%)
    pub loss_permille: u16,
    /// Available bandwidth in Kbps
    pub bandwidth_kbps: u32,
    /// Timestamp of probe
    pub timestamp: Instant,
    /// Whether probe succeeded
    pub success: bool,
}

impl ProbeResult {
    /// Create successful probe result
    pub fn success(latency_us: u32, jitter_us: u32, loss_permille: u16, bandwidth_kbps: u32) -> Self {
        Self {
            latency_us,
            jitter_us,
            loss_permille,
            bandwidth_kbps,
            timestamp: Instant::now(),
            success: true,
        }
    }

    /// Create failed probe result
    pub fn failure() -> Self {
        Self {
            latency_us: u32::MAX,
            jitter_us: u32::MAX,
            loss_permille: 10000,  // 100%
            bandwidth_kbps: 0,
            timestamp: Instant::now(),
            success: false,
        }
    }
}

/// Key for probe storage
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    /// Site identifier
    pub site: String,
    /// WAN link
    pub wan: WanLink,
}

/// Aggregated probe statistics with EWMA
#[derive(Debug)]
pub struct ProbeStats {
    /// EWMA latency in microseconds
    latency_ewma: AtomicU64,  // Stored as fixed-point (x1000)
    /// EWMA jitter in microseconds
    jitter_ewma: AtomicU64,
    /// EWMA loss permille
    loss_ewma: AtomicU64,
    /// Latest bandwidth
    bandwidth: AtomicU64,
    /// Probe count
    count: AtomicU64,
    /// Last update time
    last_update: RwLock<Instant>,
}

impl ProbeStats {
    const ALPHA: f64 = 0.2;  // EWMA smoothing factor

    /// Create new stats
    pub fn new() -> Self {
        Self {
            latency_ewma: AtomicU64::new(0),
            jitter_ewma: AtomicU64::new(0),
            loss_ewma: AtomicU64::new(0),
            bandwidth: AtomicU64::new(0),
            count: AtomicU64::new(0),
            last_update: RwLock::new(Instant::now()),
        }
    }

    /// Update with new probe result
    #[inline]
    pub fn update(&self, probe: &ProbeResult) {
        if !probe.success {
            // Failed probe - increase loss estimate
            self.update_ewma(&self.loss_ewma, 10000.0);
            return;
        }

        let count = self.count.fetch_add(1, Ordering::Relaxed);
        
        if count == 0 {
            // First probe - initialize
            self.latency_ewma.store((probe.latency_us as u64) * 1000, Ordering::Relaxed);
            self.jitter_ewma.store((probe.jitter_us as u64) * 1000, Ordering::Relaxed);
            self.loss_ewma.store((probe.loss_permille as u64) * 1000, Ordering::Relaxed);
        } else {
            // EWMA update
            self.update_ewma(&self.latency_ewma, probe.latency_us as f64);
            self.update_ewma(&self.jitter_ewma, probe.jitter_us as f64);
            self.update_ewma(&self.loss_ewma, probe.loss_permille as f64);
        }

        self.bandwidth.store(probe.bandwidth_kbps as u64, Ordering::Relaxed);
        *self.last_update.write() = Instant::now();
    }

    #[inline]
    fn update_ewma(&self, ewma: &AtomicU64, new_value: f64) {
        let current = ewma.load(Ordering::Relaxed) as f64 / 1000.0;
        let updated = Self::ALPHA * new_value + (1.0 - Self::ALPHA) * current;
        ewma.store((updated * 1000.0) as u64, Ordering::Relaxed);
    }

    /// Get current latency estimate
    #[inline]
    pub fn latency_us(&self) -> u32 {
        (self.latency_ewma.load(Ordering::Relaxed) / 1000) as u32
    }

    /// Get current jitter estimate
    #[inline]
    pub fn jitter_us(&self) -> u32 {
        (self.jitter_ewma.load(Ordering::Relaxed) / 1000) as u32
    }

    /// Get current loss estimate
    #[inline]
    pub fn loss_permille(&self) -> u16 {
        (self.loss_ewma.load(Ordering::Relaxed) / 1000) as u16
    }

    /// Get current bandwidth
    #[inline]
    pub fn bandwidth_kbps(&self) -> u32 {
        self.bandwidth.load(Ordering::Relaxed) as u32
    }

    /// Get age of stats
    pub fn age(&self) -> Duration {
        self.last_update.read().elapsed()
    }

    /// Check if stats are stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.age() > max_age
    }
}

impl Default for ProbeStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock-free probe collector
pub struct ProbeCollector {
    /// Stats per site/wan combination
    stats: DashMap<ProbeKey, ProbeStats>,
    /// Max age before stats are considered stale
    max_age: Duration,
}

impl ProbeCollector {
    /// Create new collector
    pub fn new(max_age: Duration) -> Self {
        Self {
            stats: DashMap::new(),
            max_age,
        }
    }

    /// Record a probe result
    #[inline]
    pub fn record(&self, site: &str, wan: WanLink, probe: ProbeResult) {
        let key = ProbeKey {
            site: site.to_string(),
            wan,
        };

        self.stats
            .entry(key)
            .or_insert_with(ProbeStats::new)
            .update(&probe);
    }

    /// Get stats for a site/wan
    pub fn get(&self, site: &str, wan: WanLink) -> Option<(u32, u32, u16, u32)> {
        let key = ProbeKey {
            site: site.to_string(),
            wan,
        };

        self.stats.get(&key).map(|s| {
            (s.latency_us(), s.jitter_us(), s.loss_permille(), s.bandwidth_kbps())
        })
    }

    /// Get all WAN stats for a site
    pub fn get_site(&self, site: &str) -> Vec<(WanLink, u32, u32, u16, u32)> {
        let mut results = Vec::new();
        
        for wan in [WanLink::Wan1, WanLink::Wan2, WanLink::Wan3, WanLink::Lte] {
            if let Some((lat, jit, loss, bw)) = self.get(site, wan) {
                results.push((wan, lat, jit, loss, bw));
            }
        }
        
        results
    }

    /// Clean up stale entries
    pub fn cleanup(&self) {
        self.stats.retain(|_, stats| !stats.is_stale(self.max_age));
    }
}

impl Default for ProbeCollector {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_stats_ewma() {
        let stats = ProbeStats::new();
        
        // First probe
        stats.update(&ProbeResult::success(100000, 10000, 10, 100000));
        assert_eq!(stats.latency_us(), 100000);
        
        // Second probe - EWMA should smooth
        stats.update(&ProbeResult::success(200000, 20000, 20, 100000));
        let lat = stats.latency_us();
        assert!(lat > 100000 && lat < 200000);
    }

    #[test]
    fn test_collector() {
        let collector = ProbeCollector::default();
        
        collector.record("site-a", WanLink::Wan1, ProbeResult::success(15000, 3000, 5, 100000));
        collector.record("site-a", WanLink::Wan2, ProbeResult::success(45000, 8000, 10, 50000));
        
        let stats = collector.get_site("site-a");
        assert_eq!(stats.len(), 2);
    }
}
