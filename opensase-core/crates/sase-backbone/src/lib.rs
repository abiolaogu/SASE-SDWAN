//! OpenSASE Global Backbone (OSGB)
//!
//! Global infrastructure for optimized routing between PoPs.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     GLOBAL BACKBONE (OSGB)                              │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    TRANSIT TIERS                                 │   │
//! │  │  Cloud Backbone ─► Transit Providers ─► Direct Peering (IXP)   │   │
//! │  │     (AWS/GCP)        (Cogent/NTT)      (DE-CIX/AMS-IX)         │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │  BGP Engine  │  │  PoP Mesh    │  │    Cost      │  │    CDN      │ │
//! │  │   (BIRD)     │  │  (WireGuard) │  │ Optimization │  │   Cache     │ │
//! │  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                 TRAFFIC ENGINEERING                              │   │
//! │  │   Route Selection | Path Optimization | Failover | Load Balancing│   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod bgp;
pub mod mesh;
pub mod cost;
pub mod cdn;
pub mod peering;
pub mod capacity;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;
use uuid::Uuid;

pub use bgp::{BgpManager, BgpSession, RouteDecision};
pub use mesh::{PopMesh, PopLink};
pub use cost::{CostOptimizer, ProviderCost};
pub use cdn::{CdnCache, CacheRule};
pub use peering::{PeeringManager, Peer, IxpConnection};

/// Backbone error types
#[derive(Debug, Error)]
pub enum BackboneError {
    #[error("BGP error: {0}")]
    Bgp(String),
    #[error("mesh error: {0}")]
    Mesh(String),
    #[error("cost error: {0}")]
    Cost(String),
}

/// Global Backbone Controller
pub struct GlobalBackbone {
    /// BGP management
    pub bgp: Arc<BgpManager>,
    /// Inter-PoP mesh
    pub mesh: Arc<PopMesh>,
    /// Cost optimization
    pub cost: Arc<CostOptimizer>,
    /// CDN cache
    pub cdn: Arc<CdnCache>,
    /// Peering management
    pub peering: Arc<PeeringManager>,
    /// Configuration
    pub config: Arc<RwLock<BackboneConfig>>,
}

impl GlobalBackbone {
    /// Create new backbone controller
    pub fn new(config: BackboneConfig) -> Self {
        Self {
            bgp: Arc::new(BgpManager::new(config.asn)),
            mesh: Arc::new(PopMesh::new()),
            cost: Arc::new(CostOptimizer::new()),
            cdn: Arc::new(CdnCache::new()),
            peering: Arc::new(PeeringManager::new(config.asn)),
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Select optimal path for destination
    pub fn select_path(&self, destination: &ipnetwork::IpNetwork) -> Option<RouteDecision> {
        self.bgp.select_best_path(destination)
    }

    /// Get current transit costs
    pub fn get_transit_costs(&self) -> Vec<ProviderCost> {
        self.cost.get_all_costs()
    }

    /// Get mesh latency matrix
    pub fn get_latency_matrix(&self) -> mesh::LatencyMatrix {
        self.mesh.get_latency_matrix()
    }
}

/// Backbone configuration
#[derive(Debug, Clone)]
pub struct BackboneConfig {
    /// Our AS number
    pub asn: u32,
    /// IPv4 prefix
    pub ipv4_prefix: Option<String>,
    /// IPv6 prefix
    pub ipv6_prefix: Option<String>,
    /// Transit tier preference
    pub transit_preference: TransitTier,
}

/// Transit tier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitTier {
    /// Cloud provider backbone (AWS/GCP/Azure)
    CloudBackbone,
    /// Transit providers (Cogent, NTT, etc.)
    TransitProvider,
    /// Direct peering (IXPs)
    DirectPeering,
}

impl Default for BackboneConfig {
    fn default() -> Self {
        Self {
            asn: 0, // Must be configured
            ipv4_prefix: None,
            ipv6_prefix: None,
            transit_preference: TransitTier::CloudBackbone,
        }
    }
}
