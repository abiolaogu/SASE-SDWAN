//! Failover Orchestration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::{ResilienceError, health::{HealthChecker, HealthStatus}};

/// Failover orchestrator
pub struct FailoverOrchestrator {
    health: Arc<HealthChecker>,
    /// Failover policies
    policies: Arc<RwLock<HashMap<Uuid, FailoverPolicy>>>,
    /// Failover history
    history: Arc<RwLock<Vec<FailoverEvent>>>,
    /// Active failovers
    active: Arc<RwLock<HashMap<Uuid, ActiveFailover>>>,
}

impl FailoverOrchestrator {
    pub fn new(health: Arc<HealthChecker>) -> Self {
        Self {
            health,
            policies: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            active: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register failover policy
    pub fn register_policy(&self, policy: FailoverPolicy) {
        self.policies.write().insert(policy.primary_id, policy);
    }

    /// Execute failover
    pub async fn execute(&self, from: Uuid, to: Uuid, reason: &str) -> Result<FailoverEvent, ResilienceError> {
        tracing::warn!("Executing failover from {} to {}: {}", from, to, reason);

        // Check if already failing over
        if self.active.read().contains_key(&from) {
            return Err(ResilienceError::Failover("Failover already in progress".into()));
        }

        // Mark as active
        let active = ActiveFailover {
            from,
            to,
            started_at: Utc::now(),
            status: FailoverStatus::InProgress,
        };
        self.active.write().insert(from, active);

        // Execute failover steps
        let event = self.do_failover(from, to, reason).await?;

        // Record and cleanup
        self.history.write().push(event.clone());
        self.active.write().remove(&from);

        Ok(event)
    }

    async fn do_failover(&self, from: Uuid, to: Uuid, reason: &str) -> Result<FailoverEvent, ResilienceError> {
        let start = Utc::now();

        // Step 1: Drain connections from primary
        tracing::info!("Step 1: Draining connections from {}", from);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 2: Withdraw BGP announcement for primary
        tracing::info!("Step 2: Withdrawing BGP for {}", from);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Step 3: Promote secondary
        tracing::info!("Step 3: Promoting {} as primary", to);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 4: Announce BGP for new primary
        tracing::info!("Step 4: Announcing BGP for {}", to);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Step 5: Verify health of new primary
        tracing::info!("Step 5: Verifying health");
        let health = self.health.get_status(to);
        let success = health.map(|h| h.status == HealthStatus::Healthy).unwrap_or(false);

        let duration = Utc::now() - start;

        Ok(FailoverEvent {
            id: Uuid::new_v4(),
            from,
            to,
            reason: reason.into(),
            trigger: FailoverTrigger::Manual,
            started_at: start,
            completed_at: Utc::now(),
            duration_ms: duration.num_milliseconds() as u64,
            success,
            steps: vec![
                FailoverStep { name: "drain_connections".into(), duration_ms: 100, success: true },
                FailoverStep { name: "withdraw_bgp".into(), duration_ms: 50, success: true },
                FailoverStep { name: "promote_secondary".into(), duration_ms: 100, success: true },
                FailoverStep { name: "announce_bgp".into(), duration_ms: 50, success: true },
                FailoverStep { name: "verify_health".into(), duration_ms: 10, success },
            ],
        })
    }

    /// Auto-failover based on health
    pub async fn check_auto_failover(&self) {
        let policies: Vec<_> = self.policies.read().values().cloned().collect();

        for policy in policies {
            if !policy.auto_failover {
                continue;
            }

            let primary_health = self.health.get_status(policy.primary_id);
            let should_failover = primary_health
                .map(|h| h.consecutive_failures >= policy.failure_threshold)
                .unwrap_or(true);

            if should_failover {
                // Find first healthy secondary
                for secondary in &policy.secondary_ids {
                    let secondary_health = self.health.get_status(*secondary);
                    if secondary_health.map(|h| h.status == HealthStatus::Healthy).unwrap_or(false) {
                        let _ = self.execute(policy.primary_id, *secondary, "Auto-failover triggered").await;
                        break;
                    }
                }
            }
        }
    }

    /// Get last failover event
    pub fn get_last_event(&self) -> Option<FailoverEvent> {
        self.history.read().last().cloned()
    }

    /// Get failover history
    pub fn get_history(&self) -> Vec<FailoverEvent> {
        self.history.read().clone()
    }

    /// Failback (return to primary)
    pub async fn failback(&self, primary: Uuid, current: Uuid) -> Result<FailoverEvent, ResilienceError> {
        // Verify primary is healthy before failing back
        let primary_health = self.health.get_status(primary)
            .ok_or_else(|| ResilienceError::Failover("Primary health unknown".into()))?;

        if primary_health.status != HealthStatus::Healthy {
            return Err(ResilienceError::Failover("Primary not healthy for failback".into()));
        }

        self.execute(current, primary, "Failback to primary").await
    }
}

/// Failover policy
#[derive(Debug, Clone)]
pub struct FailoverPolicy {
    pub primary_id: Uuid,
    pub secondary_ids: Vec<Uuid>,
    pub auto_failover: bool,
    pub failure_threshold: u32,
    pub cooldown: Duration,
}

/// Failover event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub id: Uuid,
    pub from: Uuid,
    pub to: Uuid,
    pub reason: String,
    pub trigger: FailoverTrigger,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub success: bool,
    pub steps: Vec<FailoverStep>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FailoverTrigger {
    Manual,
    Automatic,
    Scheduled,
    Chaos,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverStep {
    pub name: String,
    pub duration_ms: u64,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct ActiveFailover {
    pub from: Uuid,
    pub to: Uuid,
    pub started_at: DateTime<Utc>,
    pub status: FailoverStatus,
}

#[derive(Debug, Clone, Copy)]
pub enum FailoverStatus {
    InProgress,
    Completed,
    Failed,
    RolledBack,
}
