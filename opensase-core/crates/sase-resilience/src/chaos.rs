//! Chaos Engineering

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Chaos engine
pub struct ChaosEngine {
    /// Experiments
    experiments: Arc<RwLock<HashMap<Uuid, ChaosExperiment>>>,
    /// Execution history
    history: Arc<RwLock<Vec<ChaosRun>>>,
    /// Active experiments
    active: Arc<RwLock<HashMap<Uuid, ChaosRun>>>,
}

impl ChaosEngine {
    pub fn new() -> Self {
        Self {
            experiments: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            active: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register experiment
    pub fn register(&self, experiment: ChaosExperiment) -> Uuid {
        let id = experiment.id;
        self.experiments.write().insert(id, experiment);
        id
    }

    /// Run experiment
    pub async fn run(&self, experiment_id: Uuid) -> Result<ChaosRun, String> {
        let experiment = self.experiments.read().get(&experiment_id).cloned()
            .ok_or("Experiment not found")?;

        tracing::warn!("Starting chaos experiment: {}", experiment.name);

        let run = ChaosRun {
            id: Uuid::new_v4(),
            experiment_id,
            experiment_name: experiment.name.clone(),
            started_at: Utc::now(),
            completed_at: None,
            status: ChaosStatus::Running,
            injections: vec![],
            observations: vec![],
            findings: vec![],
        };

        self.active.write().insert(run.id, run.clone());

        // Execute chaos actions
        let mut completed = run;
        for action in &experiment.actions {
            let injection = self.execute_action(action).await;
            completed.injections.push(injection);
        }

        // Wait for steady state duration
        tokio::time::sleep(experiment.steady_state_duration).await;

        // Observe system behavior
        for probe in &experiment.probes {
            let observation = self.execute_probe(probe).await;
            completed.observations.push(observation);
        }

        // Rollback
        for action in &experiment.actions {
            self.rollback_action(action).await;
        }

        // Analyze findings
        completed.findings = self.analyze(&completed);
        completed.status = if completed.findings.iter().any(|f| f.severity == ChaosSeverity::Critical) {
            ChaosStatus::Failed
        } else {
            ChaosStatus::Completed
        };
        completed.completed_at = Some(Utc::now());

        self.active.write().remove(&completed.id);
        self.history.write().push(completed.clone());

        Ok(completed)
    }

    async fn execute_action(&self, action: &ChaosAction) -> ChaosInjection {
        let start = Utc::now();

        match action {
            ChaosAction::KillPod { .. } => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            ChaosAction::NetworkPartition { .. } => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            ChaosAction::LatencyInjection { .. } => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            ChaosAction::CpuStress { .. } => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            ChaosAction::DiskFill { .. } => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        ChaosInjection {
            action: format!("{:?}", action),
            injected_at: start,
            success: true,
        }
    }

    async fn rollback_action(&self, _action: &ChaosAction) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    async fn execute_probe(&self, probe: &ChaosProbe) -> ChaosObservation {
        ChaosObservation {
            probe_name: probe.name.clone(),
            observed_at: Utc::now(),
            expected: probe.expected.clone(),
            actual: probe.expected.clone(), // Simulated pass
            passed: true,
        }
    }

    fn analyze(&self, run: &ChaosRun) -> Vec<ChaosFinding> {
        let mut findings = Vec::new();

        // Check if all observations passed
        for obs in &run.observations {
            if !obs.passed {
                findings.push(ChaosFinding {
                    description: format!("Probe {} failed", obs.probe_name),
                    severity: ChaosSeverity::High,
                    recommendation: "Investigate system behavior under chaos conditions".into(),
                });
            }
        }

        findings
    }

    /// Get experiment history
    pub fn get_history(&self) -> Vec<ChaosRun> {
        self.history.read().clone()
    }
}

impl Default for ChaosEngine {
    fn default() -> Self { Self::new() }
}

/// Chaos experiment
#[derive(Debug, Clone)]
pub struct ChaosExperiment {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub hypothesis: String,
    pub actions: Vec<ChaosAction>,
    pub probes: Vec<ChaosProbe>,
    pub steady_state_duration: Duration,
    pub rollback_on_failure: bool,
}

/// Chaos action
#[derive(Debug, Clone)]
pub enum ChaosAction {
    KillPod { selector: String },
    NetworkPartition { source: String, target: String },
    LatencyInjection { target: String, latency_ms: u32 },
    CpuStress { target: String, percent: u8 },
    DiskFill { target: String, percent: u8 },
}

/// Chaos probe
#[derive(Debug, Clone)]
pub struct ChaosProbe {
    pub name: String,
    pub check_type: ChaosProbeType,
    pub expected: String,
}

#[derive(Debug, Clone)]
pub enum ChaosProbeType {
    Http { url: String, expected_status: u16 },
    Metric { query: String, threshold: f64 },
    Log { pattern: String },
}

/// Chaos run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosRun {
    pub id: Uuid,
    pub experiment_id: Uuid,
    pub experiment_name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: ChaosStatus,
    pub injections: Vec<ChaosInjection>,
    pub observations: Vec<ChaosObservation>,
    pub findings: Vec<ChaosFinding>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChaosStatus {
    Running,
    Completed,
    Failed,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosInjection {
    pub action: String,
    pub injected_at: DateTime<Utc>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosObservation {
    pub probe_name: String,
    pub observed_at: DateTime<Utc>,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosFinding {
    pub description: String,
    pub severity: ChaosSeverity,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChaosSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
