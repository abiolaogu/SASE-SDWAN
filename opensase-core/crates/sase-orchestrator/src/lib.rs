//! Global PoP Orchestrator (GPO)
//!
//! Manages 50+ global Points of Presence with:
//! - Multi-cloud deployment (AWS, GCP, Azure, Vultr, etc.)
//! - Anycast routing
//! - Automated failover
//! - Terraform/Pulumi code generation
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                      GLOBAL POP ORCHESTRATOR                            │
//! │                                                                         │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
//! │  │   Config    │  │  Terraform  │  │   Health    │  │   Anycast   │   │
//! │  │   Manager   │  │  Generator  │  │   Monitor   │  │   Router    │   │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
//! │         │                │                │                │          │
//! │         └────────────────┴────────────────┴────────────────┘          │
//! │                                  │                                     │
//! │                                  ▼                                     │
//! │  ┌───────────────────────────────────────────────────────────────┐    │
//! │  │                        PoP Fleet                               │    │
//! │  │                                                                │    │
//! │  │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐        │    │
//! │  │  │ AWS │  │ GCP │  │Azure│  │Vultr│  │ DO  │  │Eqnx │  ...   │    │
//! │  │  │ PoP │  │ PoP │  │ PoP │  │ PoP │  │ PoP │  │ PoP │        │    │
//! │  │  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘        │    │
//! │  └───────────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod pop;
pub mod provider;
pub mod terraform;
pub mod health;
pub mod anycast;
pub mod orchestrator;
pub mod pipeline;
pub mod backbone;
pub mod config;
pub mod cost;
pub mod capacity;

pub use pop::{PopDefinition, PopTier, Region, CapacitySpec};
pub use provider::CloudProvider;
pub use orchestrator::Orchestrator;
pub use pipeline::{LifecyclePipeline, LifecycleStage};
pub use backbone::BackboneMesh;
pub use config::ConfigManager;
pub use cost::CostOptimizer;
pub use capacity::CapacityPlanner;
