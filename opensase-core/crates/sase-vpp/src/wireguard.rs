//! OpenSASE VPP WireGuard Manager
//!
//! Rust API for dynamic WireGuard tunnel management via VPP API.
//! Provides high-level interface for tunnel creation, peer management,
//! and statistics collection.

use dashmap::DashMap;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// WireGuard key length (32 bytes for Curve25519)
pub const WG_KEY_LEN: usize = 32;

/// Tunnel identifier
pub type TunnelId = u32;

/// VPP WireGuard Manager errors
#[derive(Error, Debug)]
pub enum WgError {
    #[error("VPP API error: {0}")]
    VppApi(String),

    #[error("Tunnel not found: {0}")]
    TunnelNotFound(TunnelId),

    #[error("Peer not found")]
    PeerNotFound,

    #[error("Invalid key format")]
    InvalidKey,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, WgError>;

/// WireGuard tunnel configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WgTunnelConfig {
    /// Local UDP port for WireGuard
    pub local_port: u16,

    /// Private key (32 bytes)
    pub private_key: [u8; WG_KEY_LEN],

    /// Source IP address for tunnel
    pub src_ip: IpAddr,

    /// Tunnel IP address (internal)
    pub tunnel_ip: IpAddr,

    /// Tunnel IP prefix length
    pub tunnel_prefix: u8,

    /// Peers for this tunnel
    pub peers: Vec<WgPeerConfig>,
}

/// WireGuard peer configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WgPeerConfig {
    /// Peer public key (32 bytes)
    pub public_key: [u8; WG_KEY_LEN],

    /// Peer endpoint (IP:port)
    pub endpoint: SocketAddr,

    /// Allowed IP networks
    pub allowed_ips: Vec<IpNetwork>,

    /// Keepalive interval (seconds, 0 to disable)
    pub keepalive: u16,

    /// Optional preshared key for additional security
    pub preshared_key: Option<[u8; WG_KEY_LEN]>,
}

/// Tunnel runtime state
#[derive(Clone, Debug)]
pub struct WgTunnelState {
    pub sw_if_index: u32,
    pub config: WgTunnelConfig,
    pub created_at: std::time::Instant,
    pub stats: TunnelStats,
}

/// Tunnel statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TunnelStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub last_handshake: Option<std::time::SystemTime>,
}

/// Peer statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: Option<std::time::SystemTime>,
    pub endpoint: Option<SocketAddr>,
}

/// VPP API client interface (abstracted for testing)
#[async_trait::async_trait]
pub trait VppApiClient: Send + Sync {
    async fn wireguard_interface_create(
        &self,
        port: u16,
        private_key: &[u8; WG_KEY_LEN],
        src_ip: IpAddr,
    ) -> Result<u32>;

    async fn wireguard_interface_delete(&self, sw_if_index: u32) -> Result<()>;

    async fn wireguard_peer_add(
        &self,
        sw_if_index: u32,
        peer: &WgPeerConfig,
    ) -> Result<u32>;

    async fn wireguard_peer_remove(
        &self,
        sw_if_index: u32,
        public_key: &[u8; WG_KEY_LEN],
    ) -> Result<()>;

    async fn interface_set_flags(&self, sw_if_index: u32, up: bool) -> Result<()>;

    async fn interface_add_address(
        &self,
        sw_if_index: u32,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()>;

    async fn ip_route_add(
        &self,
        prefix: IpNetwork,
        next_hop: IpAddr,
    ) -> Result<()>;

    async fn wireguard_interface_dump(&self, sw_if_index: u32) -> Result<TunnelStats>;

    async fn wireguard_peers_dump(&self, sw_if_index: u32) -> Result<Vec<PeerStats>>;
}

/// VPP WireGuard Manager
///
/// Provides high-level API for managing WireGuard tunnels via VPP.
pub struct VppWireGuardManager<C: VppApiClient> {
    /// VPP API client
    client: Arc<C>,

    /// Active tunnels
    tunnels: DashMap<TunnelId, WgTunnelState>,

    /// Local IP for tunnels
    local_ip: RwLock<Option<IpAddr>>,
}

impl<C: VppApiClient> VppWireGuardManager<C> {
    /// Create a new WireGuard manager
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            tunnels: DashMap::new(),
            local_ip: RwLock::new(None),
        }
    }

    /// Set the local IP address for tunnel source
    pub async fn set_local_ip(&self, ip: IpAddr) {
        *self.local_ip.write().await = Some(ip);
    }

    /// Get local IP, or error if not set
    async fn get_local_ip(&self) -> Result<IpAddr> {
        self.local_ip
            .read()
            .await
            .ok_or_else(|| WgError::VppApi("Local IP not configured".into()))
    }

    /// Create a new WireGuard tunnel
    pub async fn create_tunnel(&self, config: WgTunnelConfig) -> Result<TunnelId> {
        let src_ip = config.src_ip;

        // Create WireGuard interface
        let sw_if_index = self
            .client
            .wireguard_interface_create(config.local_port, &config.private_key, src_ip)
            .await?;

        // Add each peer
        for peer in &config.peers {
            self.client
                .wireguard_peer_add(sw_if_index, peer)
                .await?;

            // Add routes for allowed IPs
            for allowed_ip in &peer.allowed_ips {
                // Use tunnel IP as next hop
                self.client
                    .ip_route_add(*allowed_ip, config.tunnel_ip)
                    .await
                    .ok(); // Ignore route errors (may already exist)
            }
        }

        // Assign tunnel IP address
        self.client
            .interface_add_address(sw_if_index, config.tunnel_ip, config.tunnel_prefix)
            .await?;

        // Bring interface up
        self.client
            .interface_set_flags(sw_if_index, true)
            .await?;

        // Store state
        let state = WgTunnelState {
            sw_if_index,
            config,
            created_at: std::time::Instant::now(),
            stats: TunnelStats::default(),
        };
        self.tunnels.insert(sw_if_index, state);

        tracing::info!(
            sw_if_index = sw_if_index,
            "WireGuard tunnel created"
        );

        Ok(sw_if_index)
    }

    /// Delete a WireGuard tunnel
    pub async fn delete_tunnel(&self, tunnel_id: TunnelId) -> Result<()> {
        // Remove from state
        let state = self
            .tunnels
            .remove(&tunnel_id)
            .map(|(_, v)| v)
            .ok_or(WgError::TunnelNotFound(tunnel_id))?;

        // Bring interface down
        self.client
            .interface_set_flags(state.sw_if_index, false)
            .await
            .ok();

        // Delete interface
        self.client
            .wireguard_interface_delete(state.sw_if_index)
            .await?;

        tracing::info!(
            sw_if_index = tunnel_id,
            "WireGuard tunnel deleted"
        );

        Ok(())
    }

    /// Add a peer to an existing tunnel
    pub async fn add_peer(
        &self,
        tunnel_id: TunnelId,
        peer: WgPeerConfig,
    ) -> Result<()> {
        let mut state = self
            .tunnels
            .get_mut(&tunnel_id)
            .ok_or(WgError::TunnelNotFound(tunnel_id))?;

        // Add peer to VPP
        self.client
            .wireguard_peer_add(state.sw_if_index, &peer)
            .await?;

        // Add routes
        for allowed_ip in &peer.allowed_ips {
            self.client
                .ip_route_add(*allowed_ip, state.config.tunnel_ip)
                .await
                .ok();
        }

        // Update state
        state.config.peers.push(peer);

        Ok(())
    }

    /// Remove a peer from a tunnel
    pub async fn remove_peer(
        &self,
        tunnel_id: TunnelId,
        public_key: &[u8; WG_KEY_LEN],
    ) -> Result<()> {
        let mut state = self
            .tunnels
            .get_mut(&tunnel_id)
            .ok_or(WgError::TunnelNotFound(tunnel_id))?;

        // Remove from VPP
        self.client
            .wireguard_peer_remove(state.sw_if_index, public_key)
            .await?;

        // Update state
        state
            .config
            .peers
            .retain(|p| &p.public_key != public_key);

        Ok(())
    }

    /// Get tunnel statistics
    pub async fn get_tunnel_stats(&self, tunnel_id: TunnelId) -> Result<TunnelStats> {
        let state = self
            .tunnels
            .get(&tunnel_id)
            .ok_or(WgError::TunnelNotFound(tunnel_id))?;

        self.client
            .wireguard_interface_dump(state.sw_if_index)
            .await
    }

    /// Get peer statistics for a tunnel
    pub async fn get_peer_stats(&self, tunnel_id: TunnelId) -> Result<Vec<PeerStats>> {
        let state = self
            .tunnels
            .get(&tunnel_id)
            .ok_or(WgError::TunnelNotFound(tunnel_id))?;

        self.client
            .wireguard_peers_dump(state.sw_if_index)
            .await
    }

    /// List all active tunnels
    pub fn list_tunnels(&self) -> Vec<TunnelId> {
        self.tunnels.iter().map(|r| *r.key()).collect()
    }

    /// Get tunnel configuration
    pub fn get_tunnel_config(&self, tunnel_id: TunnelId) -> Option<WgTunnelConfig> {
        self.tunnels.get(&tunnel_id).map(|r| r.config.clone())
    }
}

/// VPP socket client implementation
pub struct VppSocketClient {
    socket_path: String,
}

impl VppSocketClient {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl VppApiClient for VppSocketClient {
    async fn wireguard_interface_create(
        &self,
        port: u16,
        private_key: &[u8; WG_KEY_LEN],
        src_ip: IpAddr,
    ) -> Result<u32> {
        // TODO: Implement actual VPP API call
        // This would use vpp-api-rs or similar crate
        tracing::debug!(
            port = port,
            src_ip = %src_ip,
            "Creating WireGuard interface via VPP API"
        );
        
        // Simulated response
        Ok(1)
    }

    async fn wireguard_interface_delete(&self, sw_if_index: u32) -> Result<()> {
        tracing::debug!(sw_if_index = sw_if_index, "Deleting WireGuard interface");
        Ok(())
    }

    async fn wireguard_peer_add(
        &self,
        sw_if_index: u32,
        peer: &WgPeerConfig,
    ) -> Result<u32> {
        tracing::debug!(
            sw_if_index = sw_if_index,
            endpoint = %peer.endpoint,
            "Adding WireGuard peer"
        );
        Ok(0)
    }

    async fn wireguard_peer_remove(
        &self,
        sw_if_index: u32,
        _public_key: &[u8; WG_KEY_LEN],
    ) -> Result<()> {
        tracing::debug!(sw_if_index = sw_if_index, "Removing WireGuard peer");
        Ok(())
    }

    async fn interface_set_flags(&self, sw_if_index: u32, up: bool) -> Result<()> {
        tracing::debug!(
            sw_if_index = sw_if_index,
            up = up,
            "Setting interface flags"
        );
        Ok(())
    }

    async fn interface_add_address(
        &self,
        sw_if_index: u32,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()> {
        tracing::debug!(
            sw_if_index = sw_if_index,
            address = %address,
            prefix_len = prefix_len,
            "Adding interface address"
        );
        Ok(())
    }

    async fn ip_route_add(&self, prefix: IpNetwork, next_hop: IpAddr) -> Result<()> {
        tracing::debug!(
            prefix = %prefix,
            next_hop = %next_hop,
            "Adding IP route"
        );
        Ok(())
    }

    async fn wireguard_interface_dump(&self, _sw_if_index: u32) -> Result<TunnelStats> {
        Ok(TunnelStats::default())
    }

    async fn wireguard_peers_dump(&self, _sw_if_index: u32) -> Result<Vec<PeerStats>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    struct MockVppClient;

    #[async_trait::async_trait]
    impl VppApiClient for MockVppClient {
        async fn wireguard_interface_create(
            &self,
            _port: u16,
            _private_key: &[u8; WG_KEY_LEN],
            _src_ip: IpAddr,
        ) -> Result<u32> {
            Ok(1)
        }

        async fn wireguard_interface_delete(&self, _sw_if_index: u32) -> Result<()> {
            Ok(())
        }

        async fn wireguard_peer_add(
            &self,
            _sw_if_index: u32,
            _peer: &WgPeerConfig,
        ) -> Result<u32> {
            Ok(0)
        }

        async fn wireguard_peer_remove(
            &self,
            _sw_if_index: u32,
            _public_key: &[u8; WG_KEY_LEN],
        ) -> Result<()> {
            Ok(())
        }

        async fn interface_set_flags(&self, _sw_if_index: u32, _up: bool) -> Result<()> {
            Ok(())
        }

        async fn interface_add_address(
            &self,
            _sw_if_index: u32,
            _address: IpAddr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }

        async fn ip_route_add(&self, _prefix: IpNetwork, _next_hop: IpAddr) -> Result<()> {
            Ok(())
        }

        async fn wireguard_interface_dump(&self, _sw_if_index: u32) -> Result<TunnelStats> {
            Ok(TunnelStats {
                rx_bytes: 1000,
                tx_bytes: 2000,
                rx_packets: 10,
                tx_packets: 20,
                last_handshake: None,
            })
        }

        async fn wireguard_peers_dump(&self, _sw_if_index: u32) -> Result<Vec<PeerStats>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_create_tunnel() {
        let client = Arc::new(MockVppClient);
        let manager = VppWireGuardManager::new(client);

        let config = WgTunnelConfig {
            local_port: 51820,
            private_key: [0u8; 32],
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1)),
            tunnel_prefix: 24,
            peers: vec![WgPeerConfig {
                public_key: [1u8; 32],
                endpoint: SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(198, 51, 100, 10),
                    51820,
                )),
                allowed_ips: vec!["10.1.0.0/16".parse().unwrap()],
                keepalive: 25,
                preshared_key: None,
            }],
        };

        let tunnel_id = manager.create_tunnel(config).await.unwrap();
        assert_eq!(tunnel_id, 1);

        let tunnels = manager.list_tunnels();
        assert_eq!(tunnels.len(), 1);

        let stats = manager.get_tunnel_stats(tunnel_id).await.unwrap();
        assert_eq!(stats.rx_bytes, 1000);
    }
}
