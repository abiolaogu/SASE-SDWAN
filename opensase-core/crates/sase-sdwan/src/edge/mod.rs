//! Edge Integration Module
//!
//! Bridges flexiEdge control messages to VPP data plane.
//! Provides real-time configuration sync and health reporting.

mod integration;
mod config;
mod health;

pub use integration::EdgeIntegration;
pub use config::EdgeConfig;
pub use health::{EdgeHealth, InterfaceHealth};
