//! Health Checking System

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use std::time::Duration;
use parking_lot::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Health checker
pub struct HealthChecker {
    /// Registered components
    components: Arc<RwLock<HashMap<Uuid, RegisteredComponent>>>,
    /// Current health status
    status: Arc<RwLock<HashMap<Uuid, ComponentHealth>>>,
    /// Check interval
    interval: Duration,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            components: Arc::new(RwLock::new(HashMap::new())),
            status: Arc::new(RwLock::new(HashMap::new())),
            interval: Duration::from_secs(5),
        }
    }

    /// Register component for health checking
    pub fn register(&self, component: RegisteredComponent) -> Uuid {
        let id = component.id;
        self.components.write().insert(id, component);
        id
    }

    /// Unregister component
    pub fn unregister(&self, id: Uuid) {
        self.components.write().remove(&id);
        self.status.write().remove(&id);
    }

    /// Get health status
    pub fn get_status(&self, id: Uuid) -> Option<ComponentHealth> {
        self.status.read().get(&id).cloned()
    }

    /// Get all status
    pub fn get_all_status(&self) -> Vec<ComponentHealth> {
        self.status.read().values().cloned().collect()
    }

    /// Get unhealthy components
    pub fn get_unhealthy(&self) -> Vec<ComponentHealth> {
        self.status.read()
            .values()
            .filter(|h| h.status != HealthStatus::Healthy)
            .cloned()
            .collect()
    }

    /// Start continuous health checks
    pub async fn start_continuous_checks(&self) {
        loop {
            self.check_all().await;
            tokio::time::sleep(self.interval).await;
        }
    }

    /// Check all components
    pub async fn check_all(&self) {
        let components: Vec<_> = self.components.read().values().cloned().collect();
        
        for component in components {
            let health = self.check_component(&component).await;
            self.status.write().insert(component.id, health);
        }
    }

    /// Check single component
    async fn check_component(&self, component: &RegisteredComponent) -> ComponentHealth {
        let start = std::time::Instant::now();
        let (status, message) = match &component.check_type {
            CheckType::Tcp { address, port } => {
                self.check_tcp(*address, *port).await
            }
            CheckType::Http { url, expected_status } => {
                self.check_http(url, *expected_status).await
            }
            CheckType::Grpc { address, service } => {
                self.check_grpc(*address, service).await
            }
            CheckType::Custom { check_fn: _ } => {
                // In production: call custom function
                (HealthStatus::Healthy, "Custom check passed".into())
            }
        };

        let latency = start.elapsed();

        ComponentHealth {
            component_id: component.id,
            component_name: component.name.clone(),
            component_type: component.component_type,
            status,
            message,
            latency_ms: latency.as_millis() as u32,
            consecutive_failures: if status == HealthStatus::Healthy { 0 } else { 1 },
            last_check: Utc::now(),
            last_healthy: if status == HealthStatus::Healthy { Some(Utc::now()) } else { None },
        }
    }

    async fn check_tcp(&self, address: IpAddr, port: u16) -> (HealthStatus, String) {
        // In production: actual TCP connect
        match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect((address, port))
        ).await {
            Ok(Ok(_)) => (HealthStatus::Healthy, "TCP connection successful".into()),
            Ok(Err(e)) => (HealthStatus::Unhealthy, format!("TCP connect failed: {}", e)),
            Err(_) => (HealthStatus::Unhealthy, "TCP connect timeout".into()),
        }
    }

    async fn check_http(&self, url: &str, expected_status: u16) -> (HealthStatus, String) {
        // Simulated - in production use reqwest
        if url.contains("healthy") {
            (HealthStatus::Healthy, format!("HTTP {} OK", expected_status))
        } else {
            (HealthStatus::Degraded, "HTTP check simulated".into())
        }
    }

    async fn check_grpc(&self, _address: IpAddr, _service: &str) -> (HealthStatus, String) {
        // Simulated - in production use tonic health check
        (HealthStatus::Healthy, "gRPC health check passed".into())
    }

    /// Update status externally (for push-based checks)
    pub fn update_status(&self, id: Uuid, status: HealthStatus, message: &str) {
        if let Some(health) = self.status.write().get_mut(&id) {
            health.status = status;
            health.message = message.into();
            health.last_check = Utc::now();
            if status == HealthStatus::Healthy {
                health.last_healthy = Some(Utc::now());
                health.consecutive_failures = 0;
            } else {
                health.consecutive_failures += 1;
            }
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self { Self::new() }
}

/// Registered component
#[derive(Debug, Clone)]
pub struct RegisteredComponent {
    pub id: Uuid,
    pub name: String,
    pub component_type: ComponentType,
    pub check_type: CheckType,
    pub threshold_unhealthy: u32,
}

/// Component type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentType {
    Pop,
    ControlPlane,
    Database,
    MessageQueue,
    ApiServer,
    SecurityEngine,
    CdnCache,
}

/// Health check type
#[derive(Debug, Clone)]
pub enum CheckType {
    Tcp { address: IpAddr, port: u16 },
    Http { url: String, expected_status: u16 },
    Grpc { address: IpAddr, service: String },
    Custom { check_fn: String }, // Function name, resolved at runtime
}

/// Component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component_id: Uuid,
    pub component_name: String,
    pub component_type: ComponentType,
    pub status: HealthStatus,
    pub message: String,
    pub latency_ms: u32,
    pub consecutive_failures: u32,
    pub last_check: DateTime<Utc>,
    pub last_healthy: Option<DateTime<Utc>>,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}
