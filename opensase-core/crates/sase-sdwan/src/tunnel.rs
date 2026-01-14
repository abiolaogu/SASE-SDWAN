//! Tunnel Management Module
//!
//! WireGuard and VXLAN overlay tunnel orchestration.

use crate::{Result, SdwanError};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::{info, warn};
use uuid::Uuid;

/// Tunnel type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelType {
    WireGuard,
    Vxlan,
    Ipsec,
    Gre,
}

/// Tunnel status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelStatus {
    /// Tunnel is being configured
    Configuring,
    /// Tunnel is up and passing traffic
    Up,
    /// Tunnel is down
    Down,
    /// Tunnel has errors
    Error,
}

/// Tunnel endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEndpoint {
    pub site_id: String,
    pub device_id: String,
    pub interface: String,
    pub public_ip: Option<IpAddr>,
    pub inner_ip: IpAddr,
    pub port: u16,
}

/// Tunnel metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub loss_percent: f64,
    pub bandwidth_mbps: f64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub last_update: Option<DateTime<Utc>>,
}

/// Tunnel configuration for creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: Option<String>,
    pub tunnel_type: TunnelType,
    pub source_site: String,
    pub source_interface: String,
    pub dest_site: String,
    pub dest_interface: String,
    pub mtu: Option<u16>,
    pub keepalive_interval: Option<u16>,
}

/// WireGuard specific config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub private_key: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub listen_port: u16,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

/// Tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub tunnel_type: TunnelType,
    pub source: TunnelEndpoint,
    pub destination: TunnelEndpoint,
    pub status: TunnelStatus,
    pub metrics: TunnelMetrics,
    pub mtu: u16,
    pub wireguard: Option<WireGuardConfig>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Tunnel {
    /// Check if tunnel is healthy
    pub fn is_healthy(&self) -> bool {
        self.status == TunnelStatus::Up
    }
    
    /// Check if tunnel meets SLA
    pub fn meets_sla(&self, max_latency: f64, max_loss: f64) -> bool {
        self.metrics.latency_ms <= max_latency && self.metrics.loss_percent <= max_loss
    }
    
    /// Get tunnel age
    pub fn age(&self) -> chrono::Duration {
        Utc::now() - self.created_at
    }
}

/// Tunnel Manager
pub struct TunnelManager {
    tunnels: DashMap<String, Tunnel>,
    /// Tunnels by source site
    by_source: DashMap<String, Vec<String>>,
    /// Tunnels by destination site
    by_dest: DashMap<String, Vec<String>>,
}

impl TunnelManager {
    /// Create new tunnel manager
    pub fn new() -> Self {
        Self {
            tunnels: DashMap::new(),
            by_source: DashMap::new(),
            by_dest: DashMap::new(),
        }
    }
    
    /// Create a new tunnel
    pub async fn create_tunnel(
        &self,
        config: TunnelConfig,
        source: TunnelEndpoint,
        destination: TunnelEndpoint,
    ) -> Result<Tunnel> {
        let tunnel_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let tunnel = Tunnel {
            id: tunnel_id.clone(),
            name: config.name.unwrap_or_else(|| {
                format!("{}-to-{}", config.source_site, config.dest_site)
            }),
            tunnel_type: config.tunnel_type,
            source: source.clone(),
            destination: destination.clone(),
            status: TunnelStatus::Configuring,
            metrics: TunnelMetrics::default(),
            mtu: config.mtu.unwrap_or(1420),
            wireguard: None,
            created_at: now,
            updated_at: now,
        };
        
        info!("Creating tunnel: {} ({:?})", tunnel.name, tunnel.tunnel_type);
        
        // Store tunnel
        self.tunnels.insert(tunnel_id.clone(), tunnel.clone());
        
        // Index by source
        self.by_source.entry(source.site_id.clone())
            .or_default()
            .push(tunnel_id.clone());
        
        // Index by destination
        self.by_dest.entry(destination.site_id.clone())
            .or_default()
            .push(tunnel_id.clone());
        
        Ok(tunnel)
    }
    
    /// Get tunnel by ID
    pub fn get_tunnel(&self, id: &str) -> Option<Tunnel> {
        self.tunnels.get(id).map(|t| t.clone())
    }
    
    /// Get all tunnels
    pub fn list_tunnels(&self) -> Vec<Tunnel> {
        self.tunnels.iter().map(|t| t.clone()).collect()
    }
    
    /// Get tunnels for a site (as source or destination)
    pub fn get_site_tunnels(&self, site_id: &str) -> Vec<Tunnel> {
        let mut tunnel_ids: Vec<String> = Vec::new();
        
        if let Some(source_tunnels) = self.by_source.get(site_id) {
            tunnel_ids.extend(source_tunnels.clone());
        }
        
        if let Some(dest_tunnels) = self.by_dest.get(site_id) {
            tunnel_ids.extend(dest_tunnels.clone());
        }
        
        tunnel_ids.iter()
            .filter_map(|id| self.get_tunnel(id))
            .collect()
    }
    
    /// Update tunnel status
    pub async fn update_status(&self, id: &str, status: TunnelStatus) -> Result<()> {
        if let Some(mut tunnel) = self.tunnels.get_mut(id) {
            tunnel.status = status;
            tunnel.updated_at = Utc::now();
            info!("Tunnel {} status: {:?}", id, status);
            Ok(())
        } else {
            Err(SdwanError::TunnelError(format!("Tunnel not found: {}", id)))
        }
    }
    
    /// Update tunnel metrics
    pub async fn update_metrics(&self, id: &str, metrics: TunnelMetrics) -> Result<()> {
        if let Some(mut tunnel) = self.tunnels.get_mut(id) {
            tunnel.metrics = metrics;
            tunnel.updated_at = Utc::now();
            Ok(())
        } else {
            Err(SdwanError::TunnelError(format!("Tunnel not found: {}", id)))
        }
    }
    
    /// Create mesh topology between sites
    pub async fn create_mesh(&self, site_ids: &[String]) -> Result<Vec<Tunnel>> {
        let mut tunnels = Vec::new();
        
        for i in 0..site_ids.len() {
            for j in (i + 1)..site_ids.len() {
                let config = TunnelConfig {
                    name: Some(format!("{}-to-{}", site_ids[i], site_ids[j])),
                    tunnel_type: TunnelType::WireGuard,
                    source_site: site_ids[i].clone(),
                    source_interface: "wg0".to_string(),
                    dest_site: site_ids[j].clone(),
                    dest_interface: "wg0".to_string(),
                    mtu: Some(1420),
                    keepalive_interval: Some(25),
                };
                
                // Placeholder endpoints - would be resolved from site manager
                let source = TunnelEndpoint {
                    site_id: site_ids[i].clone(),
                    device_id: format!("device-{}", i),
                    interface: "wg0".to_string(),
                    public_ip: None,
                    inner_ip: format!("10.210.{}.1", i).parse().unwrap(),
                    port: 51820,
                };
                
                let dest = TunnelEndpoint {
                    site_id: site_ids[j].clone(),
                    device_id: format!("device-{}", j),
                    interface: "wg0".to_string(),
                    public_ip: None,
                    inner_ip: format!("10.210.{}.1", j).parse().unwrap(),
                    port: 51820,
                };
                
                let tunnel = self.create_tunnel(config, source, dest).await?;
                tunnels.push(tunnel);
            }
        }
        
        info!("Created mesh topology with {} tunnels", tunnels.len());
        Ok(tunnels)
    }
    
    /// Create hub-spoke topology
    pub async fn create_hub_spoke(
        &self,
        hub_id: &str,
        spoke_ids: &[String],
    ) -> Result<Vec<Tunnel>> {
        let mut tunnels = Vec::new();
        
        for (i, spoke_id) in spoke_ids.iter().enumerate() {
            let config = TunnelConfig {
                name: Some(format!("hub-to-{}", spoke_id)),
                tunnel_type: TunnelType::WireGuard,
                source_site: hub_id.to_string(),
                source_interface: "wg0".to_string(),
                dest_site: spoke_id.clone(),
                dest_interface: "wg0".to_string(),
                mtu: Some(1420),
                keepalive_interval: Some(25),
            };
            
            let source = TunnelEndpoint {
                site_id: hub_id.to_string(),
                device_id: "hub-device".to_string(),
                interface: "wg0".to_string(),
                public_ip: None,
                inner_ip: "10.210.0.1".parse().unwrap(),
                port: 51820,
            };
            
            let dest = TunnelEndpoint {
                site_id: spoke_id.clone(),
                device_id: format!("spoke-device-{}", i),
                interface: "wg0".to_string(),
                public_ip: None,
                inner_ip: format!("10.210.{}.1", i + 1).parse().unwrap(),
                port: 51820,
            };
            
            let tunnel = self.create_tunnel(config, source, dest).await?;
            tunnels.push(tunnel);
        }
        
        info!("Created hub-spoke topology: hub={}, {} spokes", hub_id, spoke_ids.len());
        Ok(tunnels)
    }
    
    /// Get healthy tunnels
    pub fn get_healthy_tunnels(&self) -> Vec<Tunnel> {
        self.tunnels.iter()
            .filter(|t| t.status == TunnelStatus::Up)
            .map(|t| t.clone())
            .collect()
    }
    
    /// Get tunnel count
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate WireGuard keypair
pub fn generate_wireguard_keypair() -> (String, String) {
    use x25519_dalek::{StaticSecret, PublicKey};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    
    let private_key = STANDARD.encode(secret.as_bytes());
    let public_key = STANDARD.encode(public.as_bytes());
    
    (private_key, public_key)
}
