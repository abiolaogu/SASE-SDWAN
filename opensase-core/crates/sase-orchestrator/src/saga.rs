//! Saga Orchestration for SASE Provisioning
//!
//! Adapted from BAC-Business-Activation patterns.
//! Implements saga pattern for reliable, idempotent provisioning.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Saga step status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Compensating,
    Compensated,
}

/// Saga overall status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaStatus {
    Pending,
    Running,
    Completed,
    Compensating,
    Compensated,
    Failed,
}

/// Saga step record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SagaStep {
    pub id: String,
    pub name: String,
    pub service: String,
    pub status: StepStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Saga execution record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SagaExecution {
    pub id: String,
    pub saga_type: String,
    pub status: SagaStatus,
    pub steps: Vec<SagaStep>,
    pub input: serde_json::Value,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl SagaExecution {
    pub fn new(saga_type: impl Into<String>, input: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            saga_type: saga_type.into(),
            status: SagaStatus::Pending,
            steps: vec![],
            input,
            started_at: Utc::now(),
            completed_at: None,
        }
    }
}

/// Saga step executor trait
#[async_trait]
pub trait SagaStepExecutor: Send + Sync {
    type Input;
    type Output;
    
    async fn execute(&self, input: Self::Input) -> Result<Self::Output, SagaError>;
    async fn compensate(&self, input: Self::Input) -> Result<(), SagaError>;
    
    /// Check if already completed (idempotency)
    async fn check_completion(&self, input: &Self::Input) -> Option<Self::Output> { None }
}

/// Site provisioning saga
pub struct SiteProvisioningSaga {
    steps: Vec<Box<dyn SagaStepExecutor<Input = SiteConfig, Output = StepResult> + Send + Sync>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteConfig {
    pub name: String,
    pub location: String,
    pub wan_links: Vec<WanLink>,
    pub security_profile: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WanLink {
    pub link_type: String,
    pub provider: String,
    pub bandwidth_mbps: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepResult {
    pub step_name: String,
    pub success: bool,
    pub resource_id: Option<String>,
}

#[derive(Error, Debug)]
pub enum SagaError {
    #[error("Step execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Compensation failed: {0}")]
    CompensationFailed(String),
    
    #[error("Timeout exceeded")]
    Timeout,
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Saga orchestrator
pub struct SagaOrchestrator {
    max_retries: u32,
}

impl SagaOrchestrator {
    pub fn new(max_retries: u32) -> Self {
        Self { max_retries }
    }
    
    /// Execute saga with automatic compensation on failure
    pub async fn execute<T>(&self, saga: &T, execution: &mut SagaExecution) -> Result<(), SagaError>
    where
        T: SagaDefinition,
    {
        execution.status = SagaStatus::Running;
        
        for (i, step_name) in saga.step_names().iter().enumerate() {
            let step = SagaStep {
                id: Uuid::new_v4().to_string(),
                name: step_name.clone(),
                service: saga.service_for_step(step_name),
                status: StepStatus::Running,
                started_at: Some(Utc::now()),
                completed_at: None,
                output: None,
                error: None,
            };
            execution.steps.push(step);
            
            match saga.execute_step(step_name, &execution.input).await {
                Ok(output) => {
                    if let Some(s) = execution.steps.last_mut() {
                        s.status = StepStatus::Completed;
                        s.completed_at = Some(Utc::now());
                        s.output = Some(output);
                    }
                }
                Err(e) => {
                    if let Some(s) = execution.steps.last_mut() {
                        s.status = StepStatus::Failed;
                        s.error = Some(e.to_string());
                    }
                    
                    // Compensate all completed steps in reverse
                    execution.status = SagaStatus::Compensating;
                    for j in (0..i).rev() {
                        let comp_step = &saga.step_names()[j];
                        let _ = saga.compensate_step(comp_step, &execution.input).await;
                        execution.steps[j].status = StepStatus::Compensated;
                    }
                    
                    execution.status = SagaStatus::Compensated;
                    return Err(e);
                }
            }
        }
        
        execution.status = SagaStatus::Completed;
        execution.completed_at = Some(Utc::now());
        Ok(())
    }
}

impl Default for SagaOrchestrator {
    fn default() -> Self { Self::new(3) }
}

/// Saga definition trait
#[async_trait]
pub trait SagaDefinition: Send + Sync {
    fn step_names(&self) -> Vec<String>;
    fn service_for_step(&self, step: &str) -> String;
    async fn execute_step(&self, step: &str, input: &serde_json::Value) -> Result<serde_json::Value, SagaError>;
    async fn compensate_step(&self, step: &str, input: &serde_json::Value) -> Result<(), SagaError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_saga_execution_new() {
        let input = serde_json::json!({"site": "test"});
        let exec = SagaExecution::new("site_provisioning", input);
        
        assert_eq!(exec.status, SagaStatus::Pending);
        assert!(exec.steps.is_empty());
    }
    
    #[test]
    fn test_site_config() {
        let config = SiteConfig {
            name: "branch-lagos".into(),
            location: "Lagos, Nigeria".into(),
            wan_links: vec![
                WanLink { link_type: "MPLS".into(), provider: "MTN".into(), bandwidth_mbps: 100 },
            ],
            security_profile: "standard".into(),
        };
        
        assert_eq!(config.wan_links.len(), 1);
    }
}
