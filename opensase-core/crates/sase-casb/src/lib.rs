//! Cloud Access Security Broker (CASB)

use serde::{Deserialize, Serialize};

/// CASB placeholder
pub struct CasbEngine;

impl CasbEngine {
    pub fn new() -> Self { Self }
}

impl Default for CasbEngine {
    fn default() -> Self { Self::new() }
}
