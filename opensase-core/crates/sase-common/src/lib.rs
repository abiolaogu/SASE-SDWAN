//! OpenSASE Common - Shared types for ultra-high-performance SASE
//!
//! This crate provides zero-copy, lock-free primitives for:
//! - Policy definitions
//! - Network flow keys
//! - Metrics and telemetry
//! - Error handling
//!
//! # Architecture: The Holy Trinity
//!
//! This crate follows three core principles:
//!
//! ## 1. Domain-Driven Design (DDD)
//! - **Value Objects**: Immutable, validated primitives (PolicyId, Score, Latency)
//! - **Aggregates**: Consistency boundaries (PolicyAggregate, SessionAggregate)
//! - **Domain Events**: Event sourcing support (PolicyCreated, PathSwitched)
//! - **Repositories**: Persistence abstraction
//!
//! ## 2. Extreme Programming (XP)
//! - **TDD**: All domain logic has comprehensive tests
//! - **Simple Design**: Single responsibility, minimal complexity
//! - **Continuous Refactoring**: Clean, maintainable code
//!
//! ## 3. Legacy Modernization
//! - **Anti-Corruption Layer**: Adapters for Python/FlexiWAN/OPNsense/Wazuh
//! - **Strangler Fig Pattern**: Gradual replacement of legacy components
//! - **Clean Domain**: Protected from external system quirks

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod policy;
pub mod flow;
pub mod metrics;
pub mod error;
pub mod domain;
pub mod acl;

pub use policy::*;
pub use flow::*;
pub use error::*;
pub use domain::*;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic nanosecond timestamp for sub-microsecond timing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Get current timestamp (nanoseconds since epoch)
    #[inline(always)]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self(nanos)
    }

    /// Get nanoseconds value
    #[inline(always)]
    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    /// Duration since this timestamp in microseconds
    #[inline(always)]
    pub fn elapsed_micros(&self) -> u64 {
        (Self::now().0 - self.0) / 1000
    }
}

/// High-performance counter for lock-free metrics
#[derive(Debug, Default)]
pub struct AtomicCounter(AtomicU64);

impl AtomicCounter {
    /// Create new counter
    pub const fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    /// Increment and return previous value
    #[inline(always)]
    pub fn inc(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    /// Add value and return previous
    #[inline(always)]
    pub fn add(&self, val: u64) -> u64 {
        self.0.fetch_add(val, Ordering::Relaxed)
    }

    /// Get current value
    #[inline(always)]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Memory-aligned buffer for SIMD operations
#[repr(C, align(64))]
pub struct AlignedBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> AlignedBuffer<N> {
    /// Create new aligned buffer
    pub const fn new() -> Self {
        Self {
            data: [0u8; N],
            len: 0,
        }
    }

    /// Get slice of data
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get mutable slice
    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Set length (unsafe - caller must ensure valid)
    #[inline(always)]
    pub unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= N);
        self.len = len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_precision() {
        let t1 = Timestamp::now();
        std::thread::sleep(std::time::Duration::from_micros(100));
        let t2 = Timestamp::now();
        
        // Should measure at least 100 microseconds
        assert!(t2.0 - t1.0 >= 100_000);
    }

    #[test]
    fn test_atomic_counter() {
        let counter = AtomicCounter::new(0);
        assert_eq!(counter.inc(), 0);
        assert_eq!(counter.inc(), 1);
        assert_eq!(counter.get(), 2);
    }
}
