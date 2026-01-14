//! OpenSASE Fast Path Engine (FPE)
//!
//! Ultra-high-performance data plane targeting 40Gbps+ on commodity hardware.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     FAST PATH ENGINE (FPE)                          │
//! │                                                                     │
//! │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐          │
//! │  │   Core 0      │  │   Core 1      │  │   Core N      │          │
//! │  │               │  │               │  │               │          │
//! │  │ ┌───────────┐ │  │ ┌───────────┐ │  │ ┌───────────┐ │          │
//! │  │ │ RX Queue  │ │  │ │ RX Queue  │ │  │ │ RX Queue  │ │          │
//! │  │ │ (AF_XDP)  │ │  │ │ (AF_XDP)  │ │  │ │ (AF_XDP)  │ │          │
//! │  │ └─────┬─────┘ │  │ └─────┬─────┘ │  │ └─────┬─────┘ │          │
//! │  │       │       │  │       │       │  │       │       │          │
//! │  │       ▼       │  │       ▼       │  │       ▼       │          │
//! │  │ ┌───────────┐ │  │ ┌───────────┐ │  │ ┌───────────┐ │          │
//! │  │ │Flow Table │ │  │ │Flow Table │ │  │ │Flow Table │ │          │
//! │  │ │(lockless) │ │  │ │(lockless) │ │  │ │(lockless) │ │          │
//! │  │ └─────┬─────┘ │  │ └─────┬─────┘ │  │ └─────┬─────┘ │          │
//! │  │       │       │  │       │       │  │       │       │          │
//! │  │       ▼       │  │       ▼       │  │       ▼       │          │
//! │  │ ┌───────────┐ │  │ ┌───────────┐ │  │ ┌───────────┐ │          │
//! │  │ │Transform  │ │  │ │Transform  │ │  │ │Transform  │ │          │
//! │  │ │Pipeline   │ │  │ │Pipeline   │ │  │ │Pipeline   │ │          │
//! │  │ └─────┬─────┘ │  │ └─────┬─────┘ │  │ └─────┬─────┘ │          │
//! │  │       │       │  │       │       │  │       │       │          │
//! │  │       ▼       │  │       ▼       │  │       ▼       │          │
//! │  │ ┌───────────┐ │  │ ┌───────────┐ │  │ ┌───────────┐ │          │
//! │  │ │ TX Queue  │ │  │ │ TX Queue  │ │  │ │ TX Queue  │ │          │
//! │  │ └───────────┘ │  │ └───────────┘ │  │ └───────────┘ │          │
//! │  └───────────────┘  └───────────────┘  └───────────────┘          │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Targets
//!
//! | Metric | Target | Notes |
//! |--------|--------|-------|
//! | Throughput | 40+ Gbps | With 64-byte packets |
//! | Packet Rate | 60M pps | Line rate for 40GbE |
//! | Latency | <10μs P99 | Through entire pipeline |
//! | Flows | 1M+ per core | With aging |
//!
//! # Key Optimizations
//!
//! 1. **Run-to-Completion**: No context switches per packet
//! 2. **Per-Core Isolation**: RSS steers flows to dedicated cores
//! 3. **Zero-Copy**: Hugepage-backed buffers passed by reference
//! 4. **Batch Processing**: 32-64 packets per iteration
//! 5. **Lockless Data Structures**: Wait-free flow table

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod core;
pub mod flow;
pub mod pipeline;
pub mod buffer;
pub mod stats;
pub mod crypto;

#[cfg(feature = "af_xdp")]
pub mod af_xdp;

#[cfg(feature = "io_uring")]
pub mod io_uring;

pub use core::{FastPathEngine, EngineConfig};
pub use flow::{FlowTable, FlowKey, FlowState};
pub use pipeline::{Pipeline, Stage};
pub use buffer::{PacketBuffer, BufferPool};

/// Batch size for packet processing
pub const BATCH_SIZE: usize = 64;

/// Default flow table size per core
pub const DEFAULT_FLOW_TABLE_SIZE: usize = 1 << 20;  // 1M entries

/// Default hugepage size
pub const HUGEPAGE_SIZE: usize = 2 * 1024 * 1024;  // 2MB

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(BATCH_SIZE, 64);
        assert!(DEFAULT_FLOW_TABLE_SIZE >= 1_000_000);
    }
}
