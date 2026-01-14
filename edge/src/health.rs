//! Health Monitoring

use crate::{EdgeError, network::InterfaceManager, tunnel::TunnelManager};
use std::sync::Arc;

/// Start health monitor
pub async fn start_monitor(
    interfaces: Arc<InterfaceManager>,
    tunnels: Arc<TunnelManager>,
) -> Result<(), EdgeError> {
    tracing::info!("Starting health monitor");
    
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
    
    loop {
        interval.tick().await;
        
        // Check interfaces
        for iface in interfaces.all() {
            if iface.status != crate::network::InterfaceStatus::Up {
                tracing::warn!("Interface {} is down", iface.name);
            }
        }
        
        // Check tunnels
        for tunnel in tunnels.all() {
            if tunnel.status != crate::tunnel::TunnelStatus::Connected {
                tracing::warn!("Tunnel {} is disconnected", tunnel.pop_id);
            }
        }
        
        // Report health to controller
        report_health().await;
    }
}

async fn report_health() {
    // In production: POST to controller
    tracing::debug!("Reporting health to controller");
}

/// Health status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub overall: HealthState,
    pub interfaces: Vec<ComponentHealth>,
    pub tunnels: Vec<ComponentHealth>,
    pub security: ComponentHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub name: String,
    pub state: HealthState,
    pub message: Option<String>,
}
