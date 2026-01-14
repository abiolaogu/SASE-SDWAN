//! Health Monitoring

use crate::pop::{PopInstance, PopStatus};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::time::{Duration, interval};

/// Health monitor
pub struct HealthMonitor {
    pops: Arc<RwLock<HashMap<String, PopHealth>>>,
    check_interval: Duration,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            pops: Arc::new(RwLock::new(HashMap::new())),
            check_interval: Duration::from_secs(10),
        }
    }

    /// Register PoP for monitoring
    pub fn register(&self, pop_id: &str, endpoints: Vec<HealthEndpoint>) {
        let mut pops = self.pops.write();
        pops.insert(pop_id.to_string(), PopHealth {
            pop_id: pop_id.to_string(),
            endpoints,
            status: HealthStatus::Unknown,
            last_check: 0,
            consecutive_failures: 0,
            health_score: 1.0,
        });
    }

    /// Get health status
    pub fn get_status(&self, pop_id: &str) -> Option<HealthStatus> {
        self.pops.read().get(pop_id).map(|h| h.status)
    }

    /// Get health score (0.0 - 1.0)
    pub fn get_score(&self, pop_id: &str) -> Option<f32> {
        self.pops.read().get(pop_id).map(|h| h.health_score)
    }

    /// Run health check for single PoP
    pub async fn check_pop(&self, pop_id: &str) -> HealthCheckResult {
        let endpoints = {
            let pops = self.pops.read();
            pops.get(pop_id).map(|h| h.endpoints.clone())
        };

        let endpoints = match endpoints {
            Some(e) => e,
            None => return HealthCheckResult::NotFound,
        };

        let mut passed = 0;
        let mut failed = 0;
        let mut latencies = Vec::new();

        for endpoint in &endpoints {
            match self.check_endpoint(endpoint).await {
                Ok(latency) => {
                    passed += 1;
                    latencies.push(latency);
                }
                Err(_) => failed += 1,
            }
        }

        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<u64>() / latencies.len() as u64
        } else {
            0
        };

        // Update status
        let mut pops = self.pops.write();
        if let Some(health) = pops.get_mut(pop_id) {
            health.last_check = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if failed == 0 {
                health.status = HealthStatus::Healthy;
                health.consecutive_failures = 0;
                health.health_score = 1.0;
            } else if passed > 0 {
                health.status = HealthStatus::Degraded;
                health.consecutive_failures = 0;
                health.health_score = passed as f32 / (passed + failed) as f32;
            } else {
                health.status = HealthStatus::Unhealthy;
                health.consecutive_failures += 1;
                health.health_score = 0.0;
            }
        }

        HealthCheckResult::Completed {
            passed,
            failed,
            avg_latency_ms: avg_latency,
        }
    }

    async fn check_endpoint(&self, endpoint: &HealthEndpoint) -> Result<u64, HealthError> {
        let start = std::time::Instant::now();
        
        match endpoint.check_type {
            CheckType::Http => {
                // Simulated HTTP check
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(start.elapsed().as_millis() as u64)
            }
            CheckType::Tcp => {
                // Simulated TCP check
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok(start.elapsed().as_millis() as u64)
            }
            CheckType::Icmp => {
                // Simulated ICMP ping
                tokio::time::sleep(Duration::from_millis(2)).await;
                Ok(start.elapsed().as_millis() as u64)
            }
        }
    }

    /// Get all unhealthy PoPs
    pub fn get_unhealthy(&self) -> Vec<String> {
        self.pops.read()
            .iter()
            .filter(|(_, h)| h.status == HealthStatus::Unhealthy)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-PoP health data
#[derive(Debug, Clone)]
pub struct PopHealth {
    pub pop_id: String,
    pub endpoints: Vec<HealthEndpoint>,
    pub status: HealthStatus,
    pub last_check: u64,
    pub consecutive_failures: u32,
    pub health_score: f32,
}

/// Health endpoint
#[derive(Debug, Clone)]
pub struct HealthEndpoint {
    pub url: String,
    pub check_type: CheckType,
    pub timeout_ms: u32,
}

/// Check type
#[derive(Debug, Clone, Copy)]
pub enum CheckType {
    Http,
    Tcp,
    Icmp,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

/// Health check result
#[derive(Debug)]
pub enum HealthCheckResult {
    NotFound,
    Completed {
        passed: usize,
        failed: usize,
        avg_latency_ms: u64,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("timeout")]
    Timeout,
    #[error("connection failed")]
    ConnectionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_monitor() {
        let monitor = HealthMonitor::new();
        
        monitor.register("pop-1", vec![
            HealthEndpoint {
                url: "http://pop-1/health".into(),
                check_type: CheckType::Http,
                timeout_ms: 5000,
            },
        ]);

        let result = monitor.check_pop("pop-1").await;
        assert!(matches!(result, HealthCheckResult::Completed { passed: 1, .. }));
        assert_eq!(monitor.get_status("pop-1"), Some(HealthStatus::Healthy));
    }
}
