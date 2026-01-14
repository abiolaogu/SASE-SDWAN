//! Behavioral analysis placeholder

use serde::{Deserialize, Serialize};

/// Behavioral engine
pub struct BehavioralEngine;

impl BehavioralEngine {
    pub fn new() -> Self { Self }
}

impl Default for BehavioralEngine {
    fn default() -> Self { Self::new() }
}
