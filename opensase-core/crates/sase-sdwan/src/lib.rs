//! OpenSASE SD-WAN Orchestrator (OSSO)
//!
//! FlexiWAN integration with high-performance VPP data plane.
//!
//! ## Features
//!
//! - **Site Management**: Multi-site orchestration
//! - **Tunnel Management**: WireGuard/VXLAN overlay
//! - **Policy Engine**: Application-aware routing
//! - **Path Selection**: SLA-based path optimization
//! - **FlexiWAN Integration**: Management UI and API
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    OpenSASE SD-WAN Orchestrator                  │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
//! │  │  FlexiWAN   │  │   OSSO API  │  │    VPP Integration      │  │
//! │  │ Controller  │←→│   (Rust)    │←→│  (sase-vpp + sase-path) │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod site;
pub mod tunnel;
pub mod policy;
pub mod path;
pub mod flexiwan;
pub mod vpp_bridge;
pub mod suricata;

pub use site::{Site, SiteManager, SiteConfig, SiteStatus};
pub use tunnel::{Tunnel, TunnelManager, TunnelConfig, TunnelStatus};
pub use policy::{SdwanPolicy, PolicyManager, PathPreference};
pub use path::{PathSelector, PathMetrics, SlaThresholds};
pub use flexiwan::FlexiWanClient;
pub use vpp_bridge::VppBridge;
pub use suricata::SuricataIntegration;

use thiserror::Error;

/// SD-WAN errors
#[derive(Error, Debug)]
pub enum SdwanError {
    #[error("Site not found: {0}")]
    SiteNotFound(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Tunnel error: {0}")]
    TunnelError(String),

    #[error("Policy error: {0}")]
    PolicyError(String),

    #[error("FlexiWAN API error: {0}")]
    FlexiWanError(String),

    #[error("VPP error: {0}")]
    VppError(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SdwanError>;
