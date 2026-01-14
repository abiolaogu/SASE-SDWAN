//! Tunnel Management

use crate::{EdgeError, config::PopConnection};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Tunnel manager
pub struct TunnelManager {
    tunnels: Arc<RwLock<HashMap<String, Tunnel>>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Connect to all PoPs
    pub async fn connect_all(&self, pops: &[PopConnection]) -> Result<(), EdgeError> {
        for pop in pops {
            self.connect_to_pop(pop).await?;
        }
        Ok(())
    }

    /// Connect to single PoP
    pub async fn connect_to_pop(&self, pop: &PopConnection) -> Result<(), EdgeError> {
        tracing::info!("Connecting to PoP: {}", pop.pop_id);
        
        let keypair = self.generate_keypair();
        
        let tunnel = Tunnel {
            pop_id: pop.pop_id.clone(),
            endpoint: pop.endpoint.clone(),
            local_key: keypair.public_key.clone(),
            remote_key: pop.public_key.clone(),
            status: TunnelStatus::Connected,
            stats: TunnelStats::default(),
        };
        
        self.tunnels.write().insert(pop.pop_id.clone(), tunnel);
        
        Ok(())
    }

    /// Disconnect from PoP
    pub async fn disconnect(&self, pop_id: &str) -> Result<(), EdgeError> {
        tracing::info!("Disconnecting from PoP: {}", pop_id);
        self.tunnels.write().remove(pop_id);
        Ok(())
    }

    /// Get tunnel status
    pub fn status(&self, pop_id: &str) -> Option<TunnelStatus> {
        self.tunnels.read().get(pop_id).map(|t| t.status)
    }

    /// Get all tunnels
    pub fn all(&self) -> Vec<Tunnel> {
        self.tunnels.read().values().cloned().collect()
    }

    fn generate_keypair(&self) -> WgKeyPair {
        let private = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&private);
        WgKeyPair {
            private_key: base64::encode(private.as_bytes()),
            public_key: base64::encode(public.as_bytes()),
        }
    }
}

impl Default for TunnelManager {
    fn default() -> Self { Self::new() }
}

/// Tunnel
#[derive(Debug, Clone)]
pub struct Tunnel {
    pub pop_id: String,
    pub endpoint: String,
    pub local_key: String,
    pub remote_key: String,
    pub status: TunnelStatus,
    pub stats: TunnelStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub last_handshake: u64,
}

struct WgKeyPair {
    private_key: String,
    public_key: String,
}
