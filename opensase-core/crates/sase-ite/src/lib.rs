//! Intelligent Traffic Engine (ITE)
//!
//! AI-powered traffic engineering for optimal application performance.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     INTELLIGENT TRAFFIC ENGINE                          │
//! │                                                                         │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
//! │  │    Telemetry    │  │   Application   │  │      Path       │         │
//! │  │   Collection    │  │  Classification │  │    Selection    │         │
//! │  │                 │  │                 │  │                 │         │
//! │  │ • Active probes │  │ • ML classifier │  │ • Multi-path    │         │
//! │  │ • Passive RTT   │  │ • DPI fallback  │  │ • QoS-aware     │         │
//! │  │ • App metrics   │  │ • Categories    │  │ • Cost-aware    │         │
//! │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
//! │           │                    │                    │                   │
//! │           └────────────────────┴────────────────────┘                   │
//! │                              │                                          │
//! │                              ▼                                          │
//! │  ┌──────────────────────────────────────────────────────────────────┐  │
//! │  │                    Traffic Optimizer                             │  │
//! │  │  • Real-time path switching                                      │  │
//! │  │  • SLA-aware routing                                            │  │
//! │  │  • Predictive congestion avoidance                              │  │
//! │  └──────────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod telemetry;
pub mod classifier;
pub mod path;
pub mod optimizer;
pub mod probe;
pub mod qos;
pub mod multipath;
pub mod accel;

pub use telemetry::{PathMetrics, TelemetryCollector};
pub use classifier::{AppClassifier, AppCategory, TrafficClass};
pub use path::{PathSelector, PathScore};
pub use optimizer::TrafficOptimizer;
pub use qos::{TrafficShaper, QosClass};
pub use multipath::{MultiPathManager, FecEncoder};
pub use accel::{TcpOptimizer, Http2Accelerator};
