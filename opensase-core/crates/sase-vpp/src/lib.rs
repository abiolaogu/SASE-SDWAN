//! OpenSASE VPP Integration Crate
//!
//! Provides Rust bindings for VPP API communication, WireGuard tunnel management,
//! and graph node control for the OpenSASE SASE platform.
//!
//! ## Features
//!
//! - **WireGuard Manager**: Dynamic tunnel creation and peer management
//! - **Policy Manager**: Runtime policy updates via VPP API
//! - **Statistics Collector**: Real-time metrics from VPP graph nodes
//! - **Health Monitor**: VPP process health and tunnel state monitoring

pub mod wireguard;
pub mod policy;
pub mod stats;
pub mod health;

pub use wireguard::{
    VppWireGuardManager, WgTunnelConfig, WgPeerConfig, 
    TunnelStats, PeerStats, VppApiClient, VppSocketClient,
};

use thiserror::Error;

/// VPP integration errors
#[derive(Error, Debug)]
pub enum VppError {
    #[error("WireGuard error: {0}")]
    WireGuard(#[from] wireguard::WgError),

    #[error("VPP connection error: {0}")]
    Connection(String),

    #[error("VPP API error: {0}")]
    Api(String),

    #[error("Timeout waiting for VPP response")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, VppError>;

/// VPP socket path constant
pub const VPP_API_SOCKET: &str = "/run/vpp/api.sock";
pub const VPP_CLI_SOCKET: &str = "/run/vpp/cli.sock";

/// Interface flags
#[derive(Clone, Copy, Debug)]
pub struct IfStatusFlags(u32);

impl IfStatusFlags {
    pub const ADMIN_UP: Self = Self(1);
    pub const LINK_UP: Self = Self(2);
}

/// VPP version information
#[derive(Clone, Debug)]
pub struct VppVersion {
    pub version: String,
    pub build_date: String,
    pub build_directory: String,
}

/// Connect to VPP and get version
pub async fn get_vpp_version() -> Result<VppVersion> {
    // TODO: Implement actual VPP API call
    Ok(VppVersion {
        version: "24.06".to_string(),
        build_date: "2024-06-01".to_string(),
        build_directory: "/vpp".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vpp_version() {
        let version = get_vpp_version().await.unwrap();
        assert!(!version.version.is_empty());
    }
}
