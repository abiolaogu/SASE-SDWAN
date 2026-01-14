//! Alert Pipeline
//!
//! High-performance alert aggregation and forwarding to SIEM systems.

pub mod pipeline;
pub mod cef;

pub use pipeline::{AlertPipeline, SecurityAlert, AlertPriority};
pub use cef::CefFormatter;
