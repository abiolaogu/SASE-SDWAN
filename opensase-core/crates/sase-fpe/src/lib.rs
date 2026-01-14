//! OpenSASE Fast Path Engine
//!
//! Moved to sase-dataplane for unified data plane implementation.

pub use sase_common::*;

/// Fast Path Engine placeholder
pub struct FastPathEngine;

impl FastPathEngine {
    pub fn new() -> Self { Self }
}

impl Default for FastPathEngine {
    fn default() -> Self { Self::new() }
}
