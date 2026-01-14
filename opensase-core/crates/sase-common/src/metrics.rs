//! High-performance metrics for sub-microsecond tracking

use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;

/// Lock-free histogram for latency tracking
#[derive(Debug)]
pub struct LatencyHistogram {
    /// Buckets: 0-1μs, 1-5μs, 5-10μs, 10-50μs, 50-100μs, 100-500μs, 500μs-1ms, >1ms
    buckets: [AtomicU64; 8],
    /// Total count
    count: AtomicU64,
    /// Sum for average calculation
    sum_us: AtomicU64,
    /// Min latency
    min_us: AtomicU64,
    /// Max latency
    max_us: AtomicU64,
}

impl LatencyHistogram {
    /// Create new histogram
    pub const fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
            min_us: AtomicU64::new(u64::MAX),
            max_us: AtomicU64::new(0),
        }
    }

    /// Record a latency value in microseconds
    #[inline(always)]
    pub fn record(&self, latency_us: u64) {
        let bucket = match latency_us {
            0..=1 => 0,
            2..=5 => 1,
            6..=10 => 2,
            11..=50 => 3,
            51..=100 => 4,
            101..=500 => 5,
            501..=1000 => 6,
            _ => 7,
        };

        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(latency_us, Ordering::Relaxed);

        // Update min/max
        loop {
            let current_min = self.min_us.load(Ordering::Relaxed);
            if latency_us >= current_min {
                break;
            }
            if self.min_us.compare_exchange_weak(
                current_min, latency_us, Ordering::Relaxed, Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }

        loop {
            let current_max = self.max_us.load(Ordering::Relaxed);
            if latency_us <= current_max {
                break;
            }
            if self.max_us.compare_exchange_weak(
                current_max, latency_us, Ordering::Relaxed, Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }

    /// Get average latency in microseconds
    pub fn average(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.sum_us.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Get percentile (approximate)
    pub fn percentile(&self, p: f64) -> u64 {
        let target = ((self.count.load(Ordering::Relaxed) as f64) * p) as u64;
        let mut cumulative = 0u64;

        let bucket_limits = [1, 5, 10, 50, 100, 500, 1000, 10000];

        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                return bucket_limits[i];
            }
        }

        bucket_limits[7]
    }

    /// Get P99 latency
    pub fn p99(&self) -> u64 {
        self.percentile(0.99)
    }

    /// Get snapshot
    pub fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum_us: self.sum_us.load(Ordering::Relaxed),
            min_us: self.min_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
            p50: self.percentile(0.50),
            p90: self.percentile(0.90),
            p99: self.percentile(0.99),
        }
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Histogram snapshot
#[derive(Debug, Clone)]
pub struct HistogramSnapshot {
    pub count: u64,
    pub sum_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
}

/// Throughput meter (packets/bytes per second)
#[derive(Debug, Default)]
pub struct ThroughputMeter {
    packets: AtomicU64,
    bytes: AtomicU64,
    last_snapshot: RwLock<(u64, u64, u64)>,  // (timestamp, packets, bytes)
}

impl ThroughputMeter {
    /// Record packet
    #[inline(always)]
    pub fn record(&self, bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current rates (pps, bps)
    pub fn rates(&self) -> (f64, f64) {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let current_packets = self.packets.load(Ordering::Relaxed);
        let current_bytes = self.bytes.load(Ordering::Relaxed);

        let (last_ts, last_pkts, last_bytes) = {
            let guard = self.last_snapshot.read();
            *guard
        };

        if last_ts == 0 {
            // First call
            let mut guard = self.last_snapshot.write();
            *guard = (now, current_packets, current_bytes);
            return (0.0, 0.0);
        }

        let elapsed_secs = (now - last_ts) as f64 / 1_000_000_000.0;
        if elapsed_secs < 0.001 {
            return (0.0, 0.0);
        }

        let pps = (current_packets - last_pkts) as f64 / elapsed_secs;
        let bps = (current_bytes - last_bytes) as f64 / elapsed_secs;

        // Update snapshot
        {
            let mut guard = self.last_snapshot.write();
            *guard = (now, current_packets, current_bytes);
        }

        (pps, bps)
    }
}

/// Global metrics registry
pub struct MetricsRegistry {
    pub policy_lookups: LatencyHistogram,
    pub path_decisions: LatencyHistogram,
    pub dlp_scans: LatencyHistogram,
    pub packet_throughput: ThroughputMeter,
}

impl MetricsRegistry {
    /// Create new registry
    pub const fn new() -> Self {
        Self {
            policy_lookups: LatencyHistogram::new(),
            path_decisions: LatencyHistogram::new(),
            dlp_scans: LatencyHistogram::new(),
            packet_throughput: ThroughputMeter {
                packets: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                last_snapshot: RwLock::new((0, 0, 0)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram() {
        let h = LatencyHistogram::new();
        
        h.record(1);
        h.record(5);
        h.record(10);
        h.record(50);
        h.record(100);

        assert_eq!(h.count.load(Ordering::Relaxed), 5);
        assert!(h.average() > 0.0);
    }
}
