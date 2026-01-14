//! Unified Security Inspection Engine (USIE)
//!
//! # Single-Pass Architecture
//!
//! Instead of: Packet → Firewall → IPS → Proxy → DLP (chained)
//! USIE does:  Packet → USIE (one inspection, all verdicts) → Forward/Drop
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                              USIE                                   │
//! │                                                                     │
//! │  ┌─────────────┐                                                    │
//! │  │   Packet    │                                                    │
//! │  └──────┬──────┘                                                    │
//! │         ▼                                                           │
//! │  ┌─────────────┐                                                    │
//! │  │   Parse     │──────────┐                                         │
//! │  │   ONCE      │          │                                         │
//! │  └──────┬──────┘          ▼                                         │
//! │         │          ┌─────────────┐                                  │
//! │         │          │ Inspection  │                                  │
//! │         └─────────▶│   Context   │                                  │
//! │                    └──────┬──────┘                                  │
//! │                           │                                         │
//! │     ┌─────────┬───────────┼───────────┬─────────┬─────────┐        │
//! │     ▼         ▼           ▼           ▼         ▼         ▼        │
//! │  ┌──────┐ ┌──────┐   ┌──────┐    ┌──────┐  ┌──────┐  ┌──────┐     │
//! │  │  FW  │ │ IPS  │   │ URL  │    │ DNS  │  │ DLP  │  │ AV   │     │
//! │  └──┬───┘ └──┬───┘   └──┬───┘    └──┬───┘  └──┬───┘  └──┬───┘     │
//! │     │        │          │           │         │         │          │
//! │     └────────┴──────────┴───────────┴─────────┴─────────┘          │
//! │                           │                                         │
//! │                           ▼                                         │
//! │                    ┌─────────────┐                                  │
//! │                    │  Aggregate  │                                  │
//! │                    │  Verdicts   │                                  │
//! │                    └──────┬──────┘                                  │
//! │                           ▼                                         │
//! │                    ┌─────────────┐                                  │
//! │                    │   Final     │                                  │
//! │                    │  Decision   │                                  │
//! │                    └─────────────┘                                  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Targets
//!
//! | Metric | Target |
//! |--------|--------|
//! | Cached flows | <10μs |
//! | New flow inspection | <100μs |
//! | Throughput | 1Gbps/core |

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod context;
pub mod engine;
pub mod verdict;
pub mod modules;

pub use context::{InspectionContext, VerdictSet, VerdictAction, Severity};
pub use engine::UsieEngine;
pub use verdict::AggregatedVerdict;

#[cfg(test)]
mod tests {
    #[test]
    fn test_usie_architecture() {
        // Architecture test placeholder
        assert!(true);
    }
}
