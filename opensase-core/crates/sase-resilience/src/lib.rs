//! OpenSASE Resilience Framework (OSRF)
//!
//! Disaster recovery and business continuity capabilities.
//!
//! # Recovery Targets
//!
//! | Failure Mode | RTO | RPO | Strategy |
//! |--------------|-----|-----|----------|
//! | Single PoP failure | <30s | 0 | Anycast failover |
//! | Regional outage | <5m | <1m | Cross-region failover |
//! | Cloud provider outage | <15m | <5m | Multi-cloud failover |
//! | Control plane failure | <5m | <1m | Active-standby |
//! | Data corruption | <1h | <15m | Point-in-time recovery |
//! | Complete disaster | <4h | <1h | Cold site activation |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     RESILIENCE FRAMEWORK (OSRF)                         │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    HEALTH MONITORING                             │   │
//! │  │   5s Probes | TCP/HTTP/GRPC | Anycast BGP Withdraw               │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │   Failover   │  │   Backup     │  │    Chaos     │  │  Incident   │ │
//! │  │ Orchestrator │  │   Manager    │  │  Engineering │  │  Manager    │ │
//! │  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                 MULTI-REGION / MULTI-CLOUD                       │   │
//! │  │   AWS (Primary) | GCP (Secondary) | Azure (Tertiary)            │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod health;
pub mod failover;
pub mod backup;
pub mod chaos;
pub mod incident;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;
use uuid::Uuid;
use std::time::Duration;

pub use health::{HealthChecker, HealthStatus, ComponentHealth};
pub use failover::{FailoverOrchestrator, FailoverEvent};
pub use backup::{BackupManager, BackupJob};
pub use chaos::{ChaosEngine, ChaosExperiment};
pub use incident::{IncidentManager, Incident};

/// Resilience error types
#[derive(Debug, Error)]
pub enum ResilienceError {
    #[error("health check error: {0}")]
    HealthCheck(String),
    #[error("failover error: {0}")]
    Failover(String),
    #[error("backup error: {0}")]
    Backup(String),
}

/// Resilience Framework
pub struct ResilienceFramework {
    /// Health checker
    pub health: Arc<HealthChecker>,
    /// Failover orchestrator
    pub failover: Arc<FailoverOrchestrator>,
    /// Backup manager
    pub backup: Arc<BackupManager>,
    /// Chaos engine
    pub chaos: Arc<ChaosEngine>,
    /// Incident manager
    pub incident: Arc<IncidentManager>,
    /// Configuration
    pub config: Arc<RwLock<ResilienceConfig>>,
}

impl ResilienceFramework {
    /// Create new resilience framework
    pub fn new(config: ResilienceConfig) -> Self {
        let health = Arc::new(HealthChecker::new());
        Self {
            health: health.clone(),
            failover: Arc::new(FailoverOrchestrator::new(health)),
            backup: Arc::new(BackupManager::new()),
            chaos: Arc::new(ChaosEngine::new()),
            incident: Arc::new(IncidentManager::new()),
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Start continuous health monitoring
    pub async fn start_monitoring(&self) {
        self.health.start_continuous_checks().await;
    }

    /// Trigger manual failover
    pub async fn trigger_failover(&self, from: Uuid, to: Uuid, reason: &str) -> Result<FailoverEvent, ResilienceError> {
        self.failover.execute(from, to, reason).await
    }

    /// Get current system status
    pub fn get_system_status(&self) -> SystemStatus {
        let health = self.health.get_all_status();
        let active_incidents = self.incident.get_active();
        
        SystemStatus {
            overall: if active_incidents.is_empty() { OverallStatus::Healthy } else { OverallStatus::Degraded },
            components: health,
            active_incidents: active_incidents.len(),
            last_failover: self.failover.get_last_event(),
        }
    }
}

/// Resilience configuration
#[derive(Debug, Clone)]
pub struct ResilienceConfig {
    /// Health check interval
    pub health_check_interval: Duration,
    /// Failover timeout
    pub failover_timeout: Duration,
    /// Backup retention days
    pub backup_retention_days: u32,
    /// Enable chaos engineering
    pub chaos_enabled: bool,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            health_check_interval: Duration::from_secs(5),
            failover_timeout: Duration::from_secs(30),
            backup_retention_days: 30,
            chaos_enabled: false,
        }
    }
}

/// Recovery Time Objective
#[derive(Debug, Clone, Copy)]
pub struct Rto(pub Duration);

/// Recovery Point Objective
#[derive(Debug, Clone, Copy)]
pub struct Rpo(pub Duration);

/// Recovery targets by failure mode
pub fn get_recovery_targets(mode: FailureMode) -> (Rto, Rpo) {
    match mode {
        FailureMode::SinglePop => (Rto(Duration::from_secs(30)), Rpo(Duration::ZERO)),
        FailureMode::RegionalOutage => (Rto(Duration::from_secs(300)), Rpo(Duration::from_secs(60))),
        FailureMode::CloudProviderOutage => (Rto(Duration::from_secs(900)), Rpo(Duration::from_secs(300))),
        FailureMode::ControlPlaneFailure => (Rto(Duration::from_secs(300)), Rpo(Duration::from_secs(60))),
        FailureMode::DataCorruption => (Rto(Duration::from_secs(3600)), Rpo(Duration::from_secs(900))),
        FailureMode::CompleteDisaster => (Rto(Duration::from_secs(14400)), Rpo(Duration::from_secs(3600))),
    }
}

/// Failure modes
#[derive(Debug, Clone, Copy)]
pub enum FailureMode {
    SinglePop,
    RegionalOutage,
    CloudProviderOutage,
    ControlPlaneFailure,
    DataCorruption,
    CompleteDisaster,
}

/// System status
#[derive(Debug, Clone)]
pub struct SystemStatus {
    pub overall: OverallStatus,
    pub components: Vec<ComponentHealth>,
    pub active_incidents: usize,
    pub last_failover: Option<FailoverEvent>,
}

/// Overall status
#[derive(Debug, Clone, Copy)]
pub enum OverallStatus {
    Healthy,
    Degraded,
    Outage,
}
