//! Gateway Selection and Latency Probing
//!
//! Optimal gateway selection based on latency and availability.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub struct GatewaySelector {
    gateways: parking_lot::RwLock<Vec<GatewayEndpoint>>,
    probe_results: parking_lot::RwLock<Vec<ProbeResult>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GatewayEndpoint {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub public_key: String,
    pub location: GeoLocation,
    pub capacity: GatewayCapacity,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GeoLocation {
    pub city: String,
    pub country: String,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GatewayCapacity {
    pub max_connections: u32,
    pub current_connections: u32,
    pub bandwidth_mbps: u32,
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub gateway_id: String,
    pub latency_ms: Option<u32>,
    pub success: bool,
    pub probed_at: chrono::DateTime<chrono::Utc>,
}

impl GatewaySelector {
    pub fn new() -> Self {
        Self {
            gateways: parking_lot::RwLock::new(Vec::new()),
            probe_results: parking_lot::RwLock::new(Vec::new()),
        }
    }
    
    /// Update available gateways from server
    pub fn update_gateways(&self, gateways: Vec<GatewayEndpoint>) {
        *self.gateways.write() = gateways;
    }
    
    /// Probe all gateways and select best
    pub async fn select_best(&self) -> Option<GatewayEndpoint> {
        let gateways = self.gateways.read().clone();
        let mut results = Vec::new();
        
        for gateway in &gateways {
            let latency = self.probe_latency(&gateway.host, gateway.port).await;
            results.push(ProbeResult {
                gateway_id: gateway.id.clone(),
                latency_ms: latency,
                success: latency.is_some(),
                probed_at: chrono::Utc::now(),
            });
        }
        
        *self.probe_results.write() = results.clone();
        
        // Sort by latency (available gateways first)
        let mut sorted: Vec<_> = gateways.into_iter()
            .zip(results.iter())
            .collect();
        
        sorted.sort_by_key(|(gw, result)| {
            // Consider both latency and capacity
            let latency = result.latency_ms.unwrap_or(u32::MAX);
            let load_factor = (gw.capacity.current_connections * 100) / 
                gw.capacity.max_connections.max(1);
            latency + load_factor
        });
        
        sorted.into_iter()
            .filter(|(_, r)| r.success)
            .map(|(gw, _)| gw)
            .next()
    }
    
    /// Probe latency to a gateway
    async fn probe_latency(&self, host: &str, port: u16) -> Option<u32> {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();
        
        // TCP connect probe (WireGuard uses UDP, but TCP is more reliable for probing)
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        ).await;
        
        match result {
            Ok(Ok(_)) => Some(start.elapsed().as_millis() as u32),
            _ => {
                // Fallback to UDP probe
                self.probe_udp(&addr).await
            }
        }
    }
    
    async fn probe_udp(&self, addr: &str) -> Option<u32> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let start = Instant::now();
        
        // Send a small probe packet
        socket.connect(addr).await.ok()?;
        socket.send(&[0u8; 1]).await.ok()?;
        
        Some(start.elapsed().as_millis() as u32)
    }
    
    /// Get all probe results
    pub fn get_probe_results(&self) -> Vec<ProbeResult> {
        self.probe_results.read().clone()
    }
    
    /// Get gateways sorted by latency
    pub fn get_sorted_gateways(&self) -> Vec<(GatewayEndpoint, Option<u32>)> {
        let gateways = self.gateways.read().clone();
        let results = self.probe_results.read().clone();
        
        let mut combined: Vec<_> = gateways.into_iter()
            .map(|gw| {
                let latency = results.iter()
                    .find(|r| r.gateway_id == gw.id)
                    .and_then(|r| r.latency_ms);
                (gw, latency)
            })
            .collect();
        
        combined.sort_by_key(|(_, lat)| lat.unwrap_or(u32::MAX));
        combined
    }
}

impl Default for GatewaySelector {
    fn default() -> Self { Self::new() }
}
