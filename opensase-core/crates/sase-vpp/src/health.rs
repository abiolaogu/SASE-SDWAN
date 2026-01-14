//! OpenSASE VPP Health Monitor
//!
//! Monitors VPP process health, tunnel state, and performance metrics.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::interval;

/// Health status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// VPP health report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VppHealthReport {
    /// Overall status
    pub status: HealthStatus,

    /// VPP process running
    pub vpp_running: bool,

    /// VPP API responsive
    pub api_responsive: bool,

    /// Number of workers
    pub num_workers: u32,

    /// Workers healthy
    pub workers_healthy: u32,

    /// Interfaces up
    pub interfaces_up: u32,

    /// Total interfaces
    pub total_interfaces: u32,

    /// Tunnels established
    pub tunnels_established: u32,

    /// Total tunnels
    pub total_tunnels: u32,

    /// Buffer pool utilization (0.0 - 1.0)
    pub buffer_utilization: f64,

    /// Memory usage (bytes)
    pub memory_usage: u64,

    /// Last check time
    pub last_check: std::time::SystemTime,

    /// Issues detected
    pub issues: Vec<String>,
}

impl VppHealthReport {
    /// Check if system can handle traffic
    pub fn is_operational(&self) -> bool {
        self.status == HealthStatus::Healthy || self.status == HealthStatus::Degraded
    }

    /// Get uptime percentage
    pub fn uptime_percentage(&self) -> f64 {
        if self.total_interfaces == 0 {
            return 100.0;
        }
        (self.interfaces_up as f64 / self.total_interfaces as f64) * 100.0
    }
}

/// VPP Health Monitor
pub struct VppHealthMonitor {
    /// VPP CLI socket path
    cli_socket: String,

    /// Check interval
    check_interval: Duration,

    /// Last health report
    last_report: tokio::sync::RwLock<Option<VppHealthReport>>,
}

impl VppHealthMonitor {
    /// Create new health monitor
    pub fn new(cli_socket: &str, check_interval: Duration) -> Self {
        Self {
            cli_socket: cli_socket.to_string(),
            check_interval,
            last_report: tokio::sync::RwLock::new(None),
        }
    }

    /// Run health check
    pub async fn check_health(&self) -> VppHealthReport {
        let mut issues = Vec::new();

        // Check VPP process
        let vpp_running = self.check_vpp_process().await;
        if !vpp_running {
            issues.push("VPP process not running".to_string());
        }

        // Check API
        let api_responsive = if vpp_running {
            self.check_api_responsive().await
        } else {
            false
        };
        if vpp_running && !api_responsive {
            issues.push("VPP API not responding".to_string());
        }

        // Check workers
        let (num_workers, workers_healthy) = self.check_workers().await;
        if workers_healthy < num_workers {
            issues.push(format!(
                "{}/{} workers unhealthy",
                num_workers - workers_healthy,
                num_workers
            ));
        }

        // Check interfaces
        let (total_interfaces, interfaces_up) = self.check_interfaces().await;
        if interfaces_up < total_interfaces {
            issues.push(format!(
                "{}/{} interfaces down",
                total_interfaces - interfaces_up,
                total_interfaces
            ));
        }

        // Check tunnels
        let (total_tunnels, tunnels_established) = self.check_tunnels().await;
        if tunnels_established < total_tunnels {
            issues.push(format!(
                "{}/{} tunnels not established",
                total_tunnels - tunnels_established,
                total_tunnels
            ));
        }

        // Check buffers
        let buffer_utilization = self.check_buffer_utilization().await;
        if buffer_utilization > 0.9 {
            issues.push(format!(
                "High buffer utilization: {:.1}%",
                buffer_utilization * 100.0
            ));
        }

        // Check memory
        let memory_usage = self.check_memory_usage().await;

        // Determine overall status
        let status = if !vpp_running {
            HealthStatus::Unhealthy
        } else if !api_responsive {
            HealthStatus::Unhealthy
        } else if workers_healthy < num_workers / 2 {
            HealthStatus::Unhealthy
        } else if !issues.is_empty() {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        let report = VppHealthReport {
            status,
            vpp_running,
            api_responsive,
            num_workers,
            workers_healthy,
            interfaces_up,
            total_interfaces,
            tunnels_established,
            total_tunnels,
            buffer_utilization,
            memory_usage,
            last_check: std::time::SystemTime::now(),
            issues,
        };

        // Cache report
        *self.last_report.write().await = Some(report.clone());

        report
    }

    /// Get last cached report
    pub async fn get_last_report(&self) -> Option<VppHealthReport> {
        self.last_report.read().await.clone()
    }

    /// Start background health monitoring
    pub async fn start_monitoring(self: std::sync::Arc<Self>) {
        let mut interval = interval(self.check_interval);

        loop {
            interval.tick().await;

            let report = self.check_health().await;

            if report.status == HealthStatus::Unhealthy {
                tracing::error!(
                    status = ?report.status,
                    issues = ?report.issues,
                    "VPP health check failed"
                );
            } else if report.status == HealthStatus::Degraded {
                tracing::warn!(
                    status = ?report.status,
                    issues = ?report.issues,
                    "VPP health degraded"
                );
            } else {
                tracing::debug!(
                    status = ?report.status,
                    "VPP health check passed"
                );
            }
        }
    }

    /// Check if VPP process is running
    async fn check_vpp_process(&self) -> bool {
        // Check via procfs or CLI socket existence
        tokio::fs::metadata(&self.cli_socket).await.is_ok()
    }

    /// Check if VPP API is responsive
    async fn check_api_responsive(&self) -> bool {
        // TODO: Send ping via CLI socket
        true
    }

    /// Check worker health
    async fn check_workers(&self) -> (u32, u32) {
        // TODO: Query VPP for worker status
        (16, 16)
    }

    /// Check interface status
    async fn check_interfaces(&self) -> (u32, u32) {
        // TODO: Query VPP for interface status
        (4, 4)
    }

    /// Check tunnel status
    async fn check_tunnels(&self) -> (u32, u32) {
        // TODO: Query WireGuard tunnel status
        (4, 4)
    }

    /// Check buffer pool utilization
    async fn check_buffer_utilization(&self) -> f64 {
        // TODO: Query VPP buffer stats
        0.3
    }

    /// Check memory usage
    async fn check_memory_usage(&self) -> u64 {
        // TODO: Query VPP memory usage
        8 * 1024 * 1024 * 1024 // 8GB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let monitor = VppHealthMonitor::new(
            "/run/vpp/cli.sock",
            Duration::from_secs(10),
        );

        let report = monitor.check_health().await;
        
        // Report should be generated even if VPP not running
        assert!(report.last_check <= std::time::SystemTime::now());
    }
}
