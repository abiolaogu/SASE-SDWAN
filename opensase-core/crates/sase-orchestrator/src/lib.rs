//! Global PoP Orchestrator (GPO)
//!
//! Manages 50+ global Points of Presence on dedicated servers:
//! - Dedicated server deployment (Hetzner, OVH, Scaleway, Voxility, Equinix Metal)
//! - Anycast routing with BGP
//! - Automated failover
//! - Terraform/API code generation
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
//! │  │                   DEDICATED SERVER FLEET                       │    │
//! │  │                                                                │    │
//! │  │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐            │    │
//! │  │  │Hetzn.│  │  OVH │  │Scale │  │Voxil.│  │Equinx│  ...       │    │
//! │  │  │ PoP  │  │ PoP  │  │ PoP  │  │ PoP  │  │ PoP  │            │    │
//! │  │  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘            │    │
//! │  └───────────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Dedicated Server Providers
//!
//! - **Tier 1 (Premium)**: Voxility (DDoS protection), Equinix Metal (bare metal)
//! - **Tier 2 (Cost-Effective)**: OVH Cloud, Hetzner, Scaleway
//! - **Tier 3 (Budget)**: Leaseweb, ServerHub, ReliableSite, PhoenixNap

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
pub use provider::{DedicatedProvider, CloudProvider};  // CloudProvider is alias for backwards compat
pub use orchestrator::Orchestrator;
pub use pipeline::{LifecyclePipeline, LifecycleStage};
pub use backbone::BackboneMesh;
pub use config::ConfigManager;
pub use cost::CostOptimizer;
pub use capacity::CapacityPlanner;

