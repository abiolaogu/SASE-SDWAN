//! Ultra-Fast QoE Path Selector
//!
//! Target: <5μs path decision, real-time steering
//!
//! # Features
//!
//! - Lock-free concurrent probe updates
//! - EWMA for smooth score transitions
//! - SIMD-vectorized scoring (future)
//! - Predictive path switching

#![warn(missing_docs)]

pub mod probes;
pub mod scorer;
pub mod selector;

pub use probes::{ProbeResult, ProbeCollector};
pub use scorer::{PathScorer, PathScore};
pub use selector::PathSelector;

use sase_common::AppClass;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// WAN link identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WanLink {
    /// Primary WAN
    Wan1 = 0,
    /// Secondary WAN
    Wan2 = 1,
    /// Tertiary WAN
    Wan3 = 2,
    /// LTE backup
    Lte = 3,
}

impl Default for WanLink {
    fn default() -> Self {
        Self::Wan1
    }
}

/// Path recommendation
#[derive(Debug, Clone)]
pub struct PathRecommendation {
    /// Site identifier
    pub site: String,
    /// Application class
    pub app_class: AppClass,
    /// Recommended primary path
    pub primary: WanLink,
    /// Recommended backup path
    pub backup: Option<WanLink>,
    /// Primary path score (0.0 - 1.0)
    pub primary_score: f32,
    /// Confidence in recommendation (0.0 - 1.0)
    pub confidence: f32,
    /// Reason for recommendation
    pub reason: String,
}

/// QoE thresholds for scoring
#[derive(Debug, Clone, Copy)]
pub struct QoEWeights {
    /// Latency weight (0.0 - 1.0)
    pub latency: f32,
    /// Jitter weight
    pub jitter: f32,
    /// Loss weight
    pub loss: f32,
    /// Bandwidth weight
    pub bandwidth: f32,
}

impl QoEWeights {
    /// Voice thresholds (latency-sensitive)
    pub const VOICE: Self = Self {
        latency: 0.5,
        jitter: 0.3,
        loss: 0.2,
        bandwidth: 0.0,
    };

    /// Video thresholds
    pub const VIDEO: Self = Self {
        latency: 0.4,
        jitter: 0.3,
        loss: 0.2,
        bandwidth: 0.1,
    };

    /// Web thresholds
    pub const WEB: Self = Self {
        latency: 0.6,
        jitter: 0.1,
        loss: 0.2,
        bandwidth: 0.1,
    };

    /// Bulk thresholds (bandwidth-sensitive)
    pub const BULK: Self = Self {
        latency: 0.2,
        jitter: 0.0,
        loss: 0.1,
        bandwidth: 0.7,
    };

    /// Get weights for app class
    pub const fn for_class(class: AppClass) -> Self {
        match class {
            AppClass::Voice => Self::VOICE,
            AppClass::Video => Self::VIDEO,
            AppClass::Gaming | AppClass::Interactive => Self::VIDEO,
            AppClass::Bulk => Self::BULK,
            _ => Self::WEB,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weights() {
        let w = QoEWeights::for_class(AppClass::Voice);
        assert!((w.latency + w.jitter + w.loss + w.bandwidth - 1.0).abs() < 0.01);
    }
}
