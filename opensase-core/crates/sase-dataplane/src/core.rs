//! Core Fast Path Engine
//!
//! Run-to-completion packet processing with per-core isolation.

use crate::{FlowTable, Pipeline, BufferPool, BATCH_SIZE};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use parking_lot::RwLock;
use crossbeam::channel::{Sender, Receiver, bounded};

/// Fast Path Engine configuration
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Number of worker cores
    pub num_cores: usize,
    /// Flow table size per core
    pub flow_table_size: usize,
    /// Packet batch size
    pub batch_size: usize,
    /// Enable hugepages
    pub use_hugepages: bool,
    /// Buffer pool size per core
    pub buffer_pool_size: usize,
    /// Flow aging interval (seconds)
    pub flow_aging_interval: u64,
    /// Soft timeout for flows (seconds)
    pub flow_soft_timeout: u64,
    /// Hard timeout for flows (seconds)  
    pub flow_hard_timeout: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            num_cores: num_cpus(),
            flow_table_size: 1 << 20,  // 1M flows
            batch_size: BATCH_SIZE,
            use_hugepages: true,
            buffer_pool_size: 65536,
            flow_aging_interval: 1,
            flow_soft_timeout: 60,
            flow_hard_timeout: 300,
        }
    }
}

/// Get number of CPUs (simplified)
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Fast Path Engine
/// 
/// Manages per-core packet processing workers with:
/// - Zero-copy packet buffers
/// - Lockless flow tables
/// - Run-to-completion model
pub struct FastPathEngine {
    config: EngineConfig,
    running: Arc<AtomicBool>,
    workers: Vec<WorkerHandle>,
    stats: Arc<EngineStats>,
}

/// Per-worker handle
struct WorkerHandle {
    thread: Option<thread::JoinHandle<()>>,
    core_id: usize,
}

/// Engine statistics (atomic, lock-free)
pub struct EngineStats {
    /// Packets received
    pub rx_packets: AtomicU64,
    /// Packets transmitted
    pub tx_packets: AtomicU64,
    /// Bytes received
    pub rx_bytes: AtomicU64,
    /// Bytes transmitted
    pub tx_bytes: AtomicU64,
    /// Packets dropped
    pub dropped: AtomicU64,
    /// Flow cache hits
    pub flow_hits: AtomicU64,
    /// Flow cache misses
    pub flow_misses: AtomicU64,
    /// Processing cycles
    pub cycles: AtomicU64,
}

impl Default for EngineStats {
    fn default() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            flow_hits: AtomicU64::new(0),
            flow_misses: AtomicU64::new(0),
            cycles: AtomicU64::new(0),
        }
    }
}

impl FastPathEngine {
    /// Create new engine with config
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            stats: Arc::new(EngineStats::default()),
        }
    }

    /// Start the engine
    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.running.load(Ordering::Acquire) {
            return Err(EngineError::AlreadyRunning);
        }

        self.running.store(true, Ordering::Release);
        
        // Spawn worker threads
        for core_id in 0..self.config.num_cores {
            let worker = Worker::new(
                core_id,
                self.config.clone(),
                self.running.clone(),
                self.stats.clone(),
            );

            let handle = thread::Builder::new()
                .name(format!("fpe-worker-{}", core_id))
                .spawn(move || worker.run())
                .map_err(|e| EngineError::SpawnFailed(e.to_string()))?;

            self.workers.push(WorkerHandle {
                thread: Some(handle),
                core_id,
            });
        }

        tracing::info!(
            "Fast Path Engine started with {} cores",
            self.config.num_cores
        );

        Ok(())
    }

    /// Stop the engine
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Release);
        
        for worker in &mut self.workers {
            if let Some(handle) = worker.thread.take() {
                let _ = handle.join();
            }
        }
        
        self.workers.clear();
        tracing::info!("Fast Path Engine stopped");
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Get engine stats
    pub fn stats(&self) -> EngineStatsSnapshot {
        EngineStatsSnapshot {
            rx_packets: self.stats.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.stats.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.stats.tx_bytes.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
            flow_hits: self.stats.flow_hits.load(Ordering::Relaxed),
            flow_misses: self.stats.flow_misses.load(Ordering::Relaxed),
            cycles: self.stats.cycles.load(Ordering::Relaxed),
        }
    }

    /// Get throughput in Gbps
    pub fn throughput_gbps(&self) -> f64 {
        let bytes = self.stats.rx_bytes.load(Ordering::Relaxed)
            + self.stats.tx_bytes.load(Ordering::Relaxed);
        // Rough estimate - divide by elapsed time in real implementation
        (bytes as f64 * 8.0) / 1_000_000_000.0
    }

    /// Get packet rate in Mpps
    pub fn packet_rate_mpps(&self) -> f64 {
        let packets = self.stats.rx_packets.load(Ordering::Relaxed)
            + self.stats.tx_packets.load(Ordering::Relaxed);
        packets as f64 / 1_000_000.0
    }
}

impl Drop for FastPathEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Stats snapshot
#[derive(Debug, Clone)]
pub struct EngineStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub dropped: u64,
    pub flow_hits: u64,
    pub flow_misses: u64,
    pub cycles: u64,
}

/// Per-core worker
struct Worker {
    core_id: usize,
    config: EngineConfig,
    running: Arc<AtomicBool>,
    stats: Arc<EngineStats>,
    flow_table: FlowTable,
    pipeline: Pipeline,
    buffer_pool: BufferPool,
}

impl Worker {
    fn new(
        core_id: usize,
        config: EngineConfig,
        running: Arc<AtomicBool>,
        stats: Arc<EngineStats>,
    ) -> Self {
        Self {
            core_id,
            config: config.clone(),
            running,
            stats,
            flow_table: FlowTable::new(config.flow_table_size),
            pipeline: Pipeline::new(),
            buffer_pool: BufferPool::new(config.buffer_pool_size),
        }
    }

    /// Main worker loop (run-to-completion)
    fn run(mut self) {
        tracing::debug!("Worker {} starting", self.core_id);

        // Pin to core for cache locality
        #[cfg(target_os = "linux")]
        self.pin_to_core();

        while self.running.load(Ordering::Relaxed) {
            // Process batch of packets
            self.process_batch();
            
            // Periodic flow aging
            self.flow_table.age_flows();
        }

        tracing::debug!("Worker {} stopped", self.core_id);
    }

    /// Process a batch of packets (64 at a time)
    #[inline]
    fn process_batch(&mut self) {
        // In real implementation:
        // 1. Poll RX queue (AF_XDP/DPDK)
        // 2. Look up flow for each packet
        // 3. Apply pipeline transformations
        // 4. Enqueue to TX queue
        
        // For now, simulate batch processing
        self.stats.cycles.fetch_add(1, Ordering::Relaxed);
        
        // Small yield to prevent busy-spinning in simulation
        std::hint::spin_loop();
    }

    #[cfg(target_os = "linux")]
    fn pin_to_core(&self) {
        // Use libc to set CPU affinity
        // In production, use core_affinity crate
        tracing::debug!("Pinning worker to core {}", self.core_id);
    }
}

/// Engine errors
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("engine already running")]
    AlreadyRunning,
    
    #[error("failed to spawn worker: {0}")]
    SpawnFailed(String),
    
    #[error("configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_lifecycle() {
        let config = EngineConfig {
            num_cores: 2,
            ..Default::default()
        };
        
        let mut engine = FastPathEngine::new(config);
        
        assert!(!engine.is_running());
        
        engine.start().unwrap();
        assert!(engine.is_running());
        
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        engine.stop();
        assert!(!engine.is_running());
    }

    #[test]
    fn test_stats() {
        let config = EngineConfig {
            num_cores: 1,
            ..Default::default()
        };
        
        let engine = FastPathEngine::new(config);
        let stats = engine.stats();
        
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.dropped, 0);
    }
}
