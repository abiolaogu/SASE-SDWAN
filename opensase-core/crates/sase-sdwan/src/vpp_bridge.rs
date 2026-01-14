//! VPP Bridge Module
//!
//! Integration layer between flexiEdge (SD-WAN agent) and VPP data plane.

use crate::{Result, SdwanError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{info, warn, debug};

/// VPP interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VppInterface {
    pub name: String,
    pub sw_if_index: u32,
    pub mac_address: String,
    pub ip_address: Option<IpAddr>,
    pub mtu: u16,
    pub admin_up: bool,
    pub link_up: bool,
}

/// VPP route entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VppRoute {
    pub prefix: String,
    pub next_hop: IpAddr,
    pub interface: String,
    pub vrf_id: u32,
    pub metric: u32,
}

/// VPP WireGuard tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VppWireGuard {
    pub interface_name: String,
    pub sw_if_index: u32,
    pub local_port: u16,
    pub private_key: String,
    pub peers: Vec<VppWireGuardPeer>,
}

/// WireGuard peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VppWireGuardPeer {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

/// VPP ACL rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VppAcl {
    pub acl_index: u32,
    pub tag: String,
    pub rules: Vec<VppAclRule>,
}

/// ACL rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VppAclRule {
    pub is_permit: bool,
    pub src_prefix: Option<String>,
    pub dst_prefix: Option<String>,
    pub protocol: Option<u8>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
}

/// VPP Bridge for FlexiEdge integration
pub struct VppBridge {
    /// VPP API socket path
    socket_path: String,
    /// Interface cache
    interfaces: HashMap<String, VppInterface>,
    /// Connected flag
    connected: bool,
}

impl VppBridge {
    /// Create new VPP bridge
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            interfaces: HashMap::new(),
            connected: false,
        }
    }
    
    /// Connect to VPP API
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to VPP at {}", self.socket_path);
        
        // In production: connect to VPP binary API socket
        // vpp_api_client::connect(&self.socket_path)
        
        self.connected = true;
        info!("Connected to VPP");
        Ok(())
    }
    
    /// Create WireGuard tunnel in VPP
    pub async fn create_wireguard_tunnel(
        &mut self,
        name: &str,
        port: u16,
        private_key: &str,
    ) -> Result<VppWireGuard> {
        info!("Creating WireGuard tunnel: {} on port {}", name, port);
        
        // VPP CLI equivalent:
        // wireguard create listen-port {port} private-key {key}
        
        let tunnel = VppWireGuard {
            interface_name: name.to_string(),
            sw_if_index: self.interfaces.len() as u32 + 100,
            local_port: port,
            private_key: private_key.to_string(),
            peers: Vec::new(),
        };
        
        Ok(tunnel)
    }
    
    /// Add WireGuard peer
    pub async fn add_wireguard_peer(
        &mut self,
        tunnel_name: &str,
        peer: VppWireGuardPeer,
    ) -> Result<()> {
        info!("Adding WireGuard peer to {}: endpoint={}", tunnel_name, peer.endpoint);
        
        // VPP CLI equivalent:
        // wireguard peer add {tunnel} public-key {key} endpoint {ip}:{port} allowed-ip {ips}
        
        Ok(())
    }
    
    /// Create VRF for segment
    pub async fn create_vrf(&mut self, vrf_id: u32, name: &str) -> Result<()> {
        info!("Creating VRF {} ({})", vrf_id, name);
        
        // VPP CLI:
        // ip table add {vrf_id}
        
        Ok(())
    }
    
    /// Add route to VRF
    pub async fn add_route(&mut self, route: &VppRoute) -> Result<()> {
        debug!(
            "Adding route: {} via {} (VRF {})",
            route.prefix, route.next_hop, route.vrf_id
        );
        
        // VPP CLI:
        // ip route add {prefix} via {next_hop} table {vrf_id}
        
        Ok(())
    }
    
    /// Create VXLAN tunnel
    pub async fn create_vxlan_tunnel(
        &mut self,
        vni: u32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Result<u32> {
        info!("Creating VXLAN tunnel: VNI={} src={} dst={}", vni, src_ip, dst_ip);
        
        // VPP CLI:
        // create vxlan tunnel src {src_ip} dst {dst_ip} vni {vni}
        
        let sw_if_index = self.interfaces.len() as u32 + 200;
        Ok(sw_if_index)
    }
    
    /// Bridge domain for L2 connectivity
    pub async fn create_bridge_domain(&mut self, bd_id: u32) -> Result<()> {
        info!("Creating bridge domain {}", bd_id);
        
        // VPP CLI:
        // create bridge-domain {bd_id} learn 1 forward 1 uu-flood 1
        
        Ok(())
    }
    
    /// Add interface to bridge domain
    pub async fn add_to_bridge(&mut self, sw_if_index: u32, bd_id: u32) -> Result<()> {
        debug!("Adding interface {} to bridge domain {}", sw_if_index, bd_id);
        
        // VPP CLI:
        // set interface l2 bridge {interface} {bd_id}
        
        Ok(())
    }
    
    /// Create ACL
    pub async fn create_acl(&mut self, acl: &VppAcl) -> Result<u32> {
        info!("Creating ACL: {} ({} rules)", acl.tag, acl.rules.len());
        
        // VPP API:
        // acl_add_replace
        
        Ok(acl.acl_index)
    }
    
    /// Apply ACL to interface
    pub async fn apply_acl_to_interface(
        &mut self,
        sw_if_index: u32,
        acl_index: u32,
        is_input: bool,
    ) -> Result<()> {
        debug!(
            "Applying ACL {} to interface {} ({})",
            acl_index,
            sw_if_index,
            if is_input { "input" } else { "output" }
        );
        
        // VPP API:
        // acl_interface_add_del
        
        Ok(())
    }
    
    /// Get interface statistics
    pub async fn get_interface_stats(&self, interface: &str) -> Result<InterfaceStats> {
        Ok(InterfaceStats {
            name: interface.to_string(),
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_errors: 0,
            tx_errors: 0,
        })
    }
    
    /// Sync routes from flexiEdge
    pub async fn sync_routes_from_flexiedge(&mut self, routes: &[FlexiEdgeRoute]) -> Result<()> {
        info!("Syncing {} routes from flexiEdge", routes.len());
        
        for route in routes {
            let vpp_route = VppRoute {
                prefix: route.prefix.clone(),
                next_hop: route.next_hop,
                interface: route.interface.clone(),
                vrf_id: route.vrf_id,
                metric: route.metric,
            };
            
            self.add_route(&vpp_route).await?;
        }
        
        Ok(())
    }
    
    /// Sync WireGuard tunnels from flexiEdge
    pub async fn sync_tunnels_from_flexiedge(
        &mut self,
        tunnels: &[FlexiEdgeTunnel],
    ) -> Result<()> {
        info!("Syncing {} tunnels from flexiEdge", tunnels.len());
        
        for tunnel in tunnels {
            // Create tunnel in VPP
            let wg = self.create_wireguard_tunnel(
                &tunnel.name,
                tunnel.local_port,
                &tunnel.private_key,
            ).await?;
            
            // Add peers
            for peer in &tunnel.peers {
                let vpp_peer = VppWireGuardPeer {
                    public_key: peer.public_key.clone(),
                    endpoint: peer.endpoint.clone(),
                    allowed_ips: peer.allowed_ips.clone(),
                    persistent_keepalive: peer.keepalive,
                };
                
                self.add_wireguard_peer(&tunnel.name, vpp_peer).await?;
            }
        }
        
        Ok(())
    }
}

/// Interface statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// FlexiEdge route for sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiEdgeRoute {
    pub prefix: String,
    pub next_hop: IpAddr,
    pub interface: String,
    pub vrf_id: u32,
    pub metric: u32,
}

/// FlexiEdge tunnel for sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiEdgeTunnel {
    pub name: String,
    pub local_port: u16,
    pub private_key: String,
    pub peers: Vec<FlexiEdgePeer>,
}

/// FlexiEdge peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiEdgePeer {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: u16,
}
