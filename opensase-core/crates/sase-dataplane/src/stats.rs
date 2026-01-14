//! Engine Statistics
//!
//! Lock-free metrics collection for data plane performance monitoring.

use std::sync::atomic::{AtomicU64, Ordering};

/// Per-core stats (cache-line aligned)
#[repr(C, align(64))]
pub struct CoreStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub dropped: AtomicU64,
    pub flow_hits: AtomicU64,
    pub flow_misses: AtomicU64,
    pub flow_creates: AtomicU64,
    pub pipeline_cycles: AtomicU64,
}

impl Default for CoreStats {
    fn default() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            flow_hits: AtomicU64::new(0),
            flow_misses: AtomicU64::new(0),
            flow_creates: AtomicU64::new(0),
            pipeline_cycles: AtomicU64::new(0),
        }
    }
}

impl CoreStats {
    #[inline(always)]
    pub fn record_rx(&self, bytes: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_tx(&self, bytes: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_drop(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_flow_hit(&self) {
        self.flow_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_flow_miss(&self) {
        self.flow_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CoreStatsSnapshot {
        CoreStatsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            flow_hits: self.flow_hits.load(Ordering::Relaxed),
            flow_misses: self.flow_misses.load(Ordering::Relaxed),
        }
    }
}

/// Stats snapshot (non-atomic)
#[derive(Debug, Clone, Default)]
pub struct CoreStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub dropped: u64,
    pub flow_hits: u64,
    pub flow_misses: u64,
}

impl CoreStatsSnapshot {
    pub fn throughput_gbps(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs == 0.0 { return 0.0; }
        let bytes = self.rx_bytes + self.tx_bytes;
        (bytes as f64 * 8.0) / (elapsed_secs * 1_000_000_000.0)
    }

    pub fn packet_rate_mpps(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs == 0.0 { return 0.0; }
        let packets = self.rx_packets + self.tx_packets;
        packets as f64 / (elapsed_secs * 1_000_000.0)
    }

    pub fn flow_hit_rate(&self) -> f64 {
        let total = self.flow_hits + self.flow_misses;
        if total == 0 { return 0.0; }
        self.flow_hits as f64 / total as f64
    }
}

/// Aggregate stats across all cores
pub struct AggregateStats {
    cores: Vec<CoreStats>,
}

impl AggregateStats {
    pub fn new(num_cores: usize) -> Self {
        let mut cores = Vec::with_capacity(num_cores);
        for _ in 0..num_cores {
            cores.push(CoreStats::default());
        }
        Self { cores }
    }

    pub fn core(&self, idx: usize) -> &CoreStats {
        &self.cores[idx]
    }

    pub fn total(&self) -> CoreStatsSnapshot {
        let mut total = CoreStatsSnapshot::default();
        for core in &self.cores {
            let s = core.snapshot();
            total.rx_packets += s.rx_packets;
            total.tx_packets += s.tx_packets;
            total.rx_bytes += s.rx_bytes;
            total.tx_bytes += s.tx_bytes;
            total.dropped += s.dropped;
            total.flow_hits += s.flow_hits;
            total.flow_misses += s.flow_misses;
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_stats() {
        let stats = CoreStats::default();
        stats.record_rx(1500);
        stats.record_tx(1500);
        stats.record_flow_hit();

        let snap = stats.snapshot();
        assert_eq!(snap.rx_packets, 1);
        assert_eq!(snap.rx_bytes, 1500);
        assert_eq!(snap.flow_hits, 1);
    }

    #[test]
    fn test_aggregate() {
        let agg = AggregateStats::new(4);
        agg.core(0).record_rx(1000);
        agg.core(1).record_rx(2000);

        let total = agg.total();
        assert_eq!(total.rx_packets, 2);
        assert_eq!(total.rx_bytes, 3000);
    }
}
