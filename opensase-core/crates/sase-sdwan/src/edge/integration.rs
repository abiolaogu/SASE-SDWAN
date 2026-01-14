//! Edge Integration Daemon
//!
//! Bridges flexiEdge control messages to VPP data plane.

use crate::{Result, SdwanError};
use crate::vpp_bridge::{VppBridge, VppRoute, VppAcl, VppAclRule};
use super::config::{EdgeConfig, InterfaceConfig, TunnelConfig, RouteConfig, PolicyConfig};
use super::health::{EdgeHealth, InterfaceHealth, TunnelHealth};

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Instant};
use tracing::{info, warn, error, debug};

/// Edge integration daemon
pub struct EdgeIntegration {
    /// FlexiEdge WebSocket client
    flexiedge_rx: mpsc::Receiver<EdgeConfig>,
    /// Health report sender
    health_tx: mpsc::Sender<EdgeHealth>,
    /// VPP bridge
    vpp: Arc<RwLock<VppBridge>>,
    /// Current configuration
    current_config: Option<EdgeConfig>,
    /// Edge name
    edge_name: String,
    /// Last config update time
    last_config_update: Option<Instant>,
}

impl EdgeIntegration {
    /// Create new edge integration
    pub fn new(
        edge_name: &str,
        flexiedge_rx: mpsc::Receiver<EdgeConfig>,
        health_tx: mpsc::Sender<EdgeHealth>,
        vpp: VppBridge,
    ) -> Self {
        Self {
            flexiedge_rx,
            health_tx,
            vpp: Arc::new(RwLock::new(vpp)),
            current_config: None,
            edge_name: edge_name.to_string(),
            last_config_update: None,
        }
    }
    
    /// Run the integration daemon
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting edge integration daemon for: {}", self.edge_name);
        
        // Connect to VPP
        {
            let mut vpp = self.vpp.write().await;
            vpp.connect().await?;
        }
        
        // Health check interval
        let mut health_interval = interval(Duration::from_secs(30));
        
        loop {
            tokio::select! {
                // Configuration updates from flexiEdge
                Some(config) = self.flexiedge_rx.recv() => {
                    info!("Received configuration update");
                    if let Err(e) = self.apply_config(config).await {
                        error!("Failed to apply config: {}", e);
                    }
                }
                
                // Periodic health reporting
                _ = health_interval.tick() => {
                    if let Err(e) = self.report_health().await {
                        warn!("Failed to report health: {}", e);
                    }
                }
            }
        }
    }
    
    /// Apply configuration from flexiEdge
    async fn apply_config(&mut self, config: EdgeConfig) -> Result<()> {
        let start = Instant::now();
        
        info!("Applying configuration: {} interfaces, {} tunnels, {} routes, {} policies",
            config.interfaces.len(),
            config.tunnels.len(),
            config.routes.len(),
            config.policies.len()
        );
        
        // 1. Apply interface configuration
        for iface in &config.interfaces {
            self.configure_interface(iface).await?;
        }
        
        // 2. Apply tunnel configuration
        for tunnel in &config.tunnels {
            self.configure_tunnel(tunnel).await?;
        }
        
        // 3. Apply routing
        for route in &config.routes {
            self.apply_route(route).await?;
        }
        
        // 4. Apply policies
        for policy in &config.policies {
            self.apply_policy(policy).await?;
        }
        
        self.current_config = Some(config);
        self.last_config_update = Some(Instant::now());
        
        info!("Configuration applied in {:?}", start.elapsed());
        Ok(())
    }
    
    /// Configure interface in VPP
    async fn configure_interface(&self, iface: &InterfaceConfig) -> Result<()> {
        debug!("Configuring interface: {} ({})", iface.name, iface.role);
        
        let mut vpp = self.vpp.write().await;
        
        // Interface already exists in VPP, just configure IP
        if let Some(ref ip) = iface.ip_address {
            // VPP CLI: set interface ip address {name} {ip}/{mask}
            debug!("Setting IP {} on {}", ip, iface.name);
        }
        
        // Set interface up
        // VPP CLI: set interface state {name} up
        
        // Apply VRF if specified
        if let Some(vrf_id) = iface.vrf_id {
            vpp.create_vrf(vrf_id, &format!("vrf-{}", vrf_id)).await?;
            // VPP CLI: set interface ip table {name} {vrf_id}
        }
        
        Ok(())
    }
    
    /// Configure tunnel in VPP
    async fn configure_tunnel(&self, tunnel: &TunnelConfig) -> Result<()> {
        info!("Configuring tunnel: {} ({:?})", tunnel.name, tunnel.tunnel_type);
        
        let mut vpp = self.vpp.write().await;
        
        match tunnel.tunnel_type {
            TunnelType::WireGuard => {
                // Create WireGuard tunnel
                let wg = vpp.create_wireguard_tunnel(
                    &tunnel.name,
                    tunnel.local_port,
                    &tunnel.private_key,
                ).await?;
                
                // Add peers
                for peer in &tunnel.peers {
                    let vpp_peer = crate::vpp_bridge::VppWireGuardPeer {
                        public_key: peer.public_key.clone(),
                        endpoint: peer.endpoint.clone(),
                        allowed_ips: peer.allowed_ips.clone(),
                        persistent_keepalive: peer.keepalive,
                    };
                    
                    vpp.add_wireguard_peer(&tunnel.name, vpp_peer).await?;
                }
            }
            
            TunnelType::Vxlan => {
                // Create VXLAN tunnel
                if let (Some(vni), Some(remote)) = (tunnel.vni, tunnel.remote_ip) {
                    vpp.create_vxlan_tunnel(
                        vni,
                        tunnel.local_ip.unwrap(),
                        remote,
                    ).await?;
                }
            }
            
            TunnelType::Gre => {
                // Create GRE tunnel
                debug!("GRE tunnel: {} -> {:?}", tunnel.name, tunnel.remote_ip);
            }
            
            TunnelType::Ipsec => {
                // IPsec tunnel
                debug!("IPsec tunnel: {}", tunnel.name);
            }
        }
        
        Ok(())
    }
    
    /// Apply route to VPP
    async fn apply_route(&self, route: &RouteConfig) -> Result<()> {
        debug!("Applying route: {} via {:?}", route.prefix, route.next_hop);
        
        let vpp = self.vpp.write().await;
        
        let vpp_route = VppRoute {
            prefix: route.prefix.clone(),
            next_hop: route.next_hop,
            interface: route.interface.clone().unwrap_or_default(),
            vrf_id: route.vrf_id.unwrap_or(0),
            metric: route.metric,
        };
        
        vpp.add_route(&vpp_route).await?;
        
        Ok(())
    }
    
    /// Apply policy to VPP
    async fn apply_policy(&self, policy: &PolicyConfig) -> Result<()> {
        debug!("Applying policy: {} (type: {:?})", policy.name, policy.policy_type);
        
        let mut vpp = self.vpp.write().await;
        
        match policy.policy_type {
            PolicyType::Acl => {
                // Create ACL rules
                let rules: Vec<VppAclRule> = policy.rules.iter().map(|r| {
                    VppAclRule {
                        is_permit: r.action == "permit",
                        src_prefix: r.source.clone(),
                        dst_prefix: r.destination.clone(),
                        protocol: r.protocol,
                        src_port_start: r.src_port_start,
                        src_port_end: r.src_port_end,
                        dst_port_start: r.dst_port_start,
                        dst_port_end: r.dst_port_end,
                    }
                }).collect();
                
                let acl = VppAcl {
                    acl_index: 0,
                    tag: policy.name.clone(),
                    rules,
                };
                
                let acl_index = vpp.create_acl(&acl).await?;
                
                // Apply to interfaces
                for iface_idx in &policy.interfaces {
                    vpp.apply_acl_to_interface(*iface_idx, acl_index, true).await?;
                }
            }
            
            PolicyType::Nat => {
                // NAT policy
                debug!("NAT policy: {}", policy.name);
            }
            
            PolicyType::Qos => {
                // QoS policy
                debug!("QoS policy: {}", policy.name);
            }
            
            PolicyType::Routing => {
                // Routing policy
                debug!("Routing policy: {}", policy.name);
            }
        }
        
        Ok(())
    }
    
    /// Report health to flexiEdge
    async fn report_health(&self) -> Result<()> {
        let vpp = self.vpp.read().await;
        
        // Collect interface stats
        let mut interfaces = Vec::new();
        
        // In production: iterate through configured interfaces
        if let Some(ref config) = self.current_config {
            for iface in &config.interfaces {
                let stats = vpp.get_interface_stats(&iface.name).await?;
                
                interfaces.push(InterfaceHealth {
                    name: iface.name.clone(),
                    rx_bytes: stats.rx_bytes,
                    tx_bytes: stats.tx_bytes,
                    rx_packets: stats.rx_packets,
                    tx_packets: stats.tx_packets,
                    status: "up".to_string(),
                });
            }
        }
        
        // Collect tunnel stats
        let tunnels = Vec::new(); // Would collect from tunnel manager
        
        let health = EdgeHealth {
            timestamp: chrono::Utc::now(),
            edge_name: self.edge_name.clone(),
            cpu_usage: get_cpu_usage(),
            memory_usage: get_memory_usage(),
            interfaces,
            tunnels,
            config_age_secs: self.last_config_update
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0),
        };
        
        self.health_tx.send(health).await
            .map_err(|e| SdwanError::PolicyError(e.to_string()))?;
        
        debug!("Health report sent");
        Ok(())
    }
}

// Helper functions

fn get_cpu_usage() -> f64 {
    // Read from /proc/stat in production
    0.0
}

fn get_memory_usage() -> f64 {
    // Read from /proc/meminfo in production
    0.0
}

/// Tunnel type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelType {
    WireGuard,
    Vxlan,
    Gre,
    Ipsec,
}

/// Policy type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyType {
    Acl,
    Nat,
    Qos,
    Routing,
}
