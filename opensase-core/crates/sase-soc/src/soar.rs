//! SOAR Engine
//!
//! Security Orchestration, Automation, and Response.

use crate::{SecurityAlert, SecurityEvent, Severity, AlertStatus};
use std::collections::HashMap;

/// SOAR automation engine
pub struct SoarEngine {
    /// Playbooks
    playbooks: dashmap::DashMap<String, Playbook>,
    /// Running executions
    executions: dashmap::DashMap<String, PlaybookExecution>,
    /// Action handlers
    actions: dashmap::DashMap<String, Box<dyn ActionHandler>>,
    /// Stats
    execution_count: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger: PlaybookTrigger,
    pub steps: Vec<PlaybookStep>,
    pub enabled: bool,
    pub timeout_secs: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub enum PlaybookTrigger {
    AlertType(String),
    Severity(Severity),
    MitreAttack { tactics: Vec<String>, techniques: Vec<String> },
    Indicator { indicator_type: String },
    Schedule { cron: String },
    Manual,
}

#[derive(Clone)]
pub struct PlaybookStep {
    pub id: String,
    pub name: String,
    pub action: PlaybookAction,
    pub condition: Option<StepCondition>,
    pub on_success: Option<String>,
    pub on_failure: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Clone)]
pub enum PlaybookAction {
    // Enrichment
    EnrichIndicator { types: Vec<String> },
    LookupAsset { by: String },
    LookupUser { by: String },
    QuerySiem { query: String },
    
    // Response
    BlockIp { ip_field: String },
    IsolateHost { host_field: String },
    DisableUser { user_field: String },
    QuarantineFile { hash_field: String },
    
    // Notification
    SendEmail { recipients: Vec<String>, template: String },
    SendSlack { channel: String, template: String },
    CreateTicket { system: String, template: String },
    PageOnCall { team: String },
    
    // Case management
    CreateCase { template: String },
    UpdateCase { field: String, value: String },
    EscalateCase { to: String },
    
    // Custom
    RunScript { script: String, args: HashMap<String, String> },
    CallApi { url: String, method: String, body: Option<String> },
    
    // Control flow
    Wait { seconds: u64 },
    Parallel { steps: Vec<String> },
    Conditional { condition: String, then_step: String, else_step: Option<String> },
}

#[derive(Clone)]
pub struct StepCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
}

#[derive(Clone, Copy)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
    Exists,
}

#[derive(Clone)]
pub struct PlaybookExecution {
    pub id: String,
    pub playbook_id: String,
    pub alert_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: ExecutionStatus,
    pub current_step: Option<String>,
    pub step_results: HashMap<String, StepResult>,
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Clone)]
pub struct StepResult {
    pub step_id: String,
    pub status: StepStatus,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[async_trait::async_trait]
pub trait ActionHandler: Send + Sync {
    fn action_type(&self) -> &str;
    async fn execute(
        &self,
        action: &PlaybookAction,
        context: &mut HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value, ActionError>;
}

impl SoarEngine {
    pub fn new() -> Self {
        let engine = Self {
            playbooks: dashmap::DashMap::new(),
            executions: dashmap::DashMap::new(),
            actions: dashmap::DashMap::new(),
            execution_count: std::sync::atomic::AtomicU64::new(0),
        };
        
        engine.load_default_playbooks();
        engine
    }
    
    fn load_default_playbooks(&self) {
        // Malware response playbook
        self.register_playbook(Playbook {
            id: "malware-response".to_string(),
            name: "Malware Response".to_string(),
            description: "Automated malware incident response".to_string(),
            trigger: PlaybookTrigger::AlertType("MalwareDetected".to_string()),
            steps: vec![
                PlaybookStep {
                    id: "enrich".to_string(),
                    name: "Enrich Indicators".to_string(),
                    action: PlaybookAction::EnrichIndicator { 
                        types: vec!["hash".to_string(), "ip".to_string()] 
                    },
                    condition: None,
                    on_success: Some("isolate".to_string()),
                    on_failure: Some("notify".to_string()),
                    timeout_secs: 30,
                },
                PlaybookStep {
                    id: "isolate".to_string(),
                    name: "Isolate Host".to_string(),
                    action: PlaybookAction::IsolateHost { 
                        host_field: "source_host".to_string() 
                    },
                    condition: Some(StepCondition {
                        field: "severity".to_string(),
                        operator: ConditionOperator::GreaterThan,
                        value: "Medium".to_string(),
                    }),
                    on_success: Some("case".to_string()),
                    on_failure: Some("notify".to_string()),
                    timeout_secs: 60,
                },
                PlaybookStep {
                    id: "case".to_string(),
                    name: "Create Case".to_string(),
                    action: PlaybookAction::CreateCase { 
                        template: "malware-incident".to_string() 
                    },
                    condition: None,
                    on_success: Some("notify".to_string()),
                    on_failure: Some("notify".to_string()),
                    timeout_secs: 30,
                },
                PlaybookStep {
                    id: "notify".to_string(),
                    name: "Notify Team".to_string(),
                    action: PlaybookAction::SendSlack { 
                        channel: "#security-alerts".to_string(),
                        template: "malware-alert".to_string(),
                    },
                    condition: None,
                    on_success: None,
                    on_failure: None,
                    timeout_secs: 10,
                },
            ],
            enabled: true,
            timeout_secs: 300,
            created_at: chrono::Utc::now(),
        });
        
        // Brute force response playbook
        self.register_playbook(Playbook {
            id: "brute-force-response".to_string(),
            name: "Brute Force Response".to_string(),
            description: "Block brute force attempts".to_string(),
            trigger: PlaybookTrigger::AlertType("BruteForceAttempt".to_string()),
            steps: vec![
                PlaybookStep {
                    id: "block".to_string(),
                    name: "Block IP".to_string(),
                    action: PlaybookAction::BlockIp { 
                        ip_field: "source_ip".to_string() 
                    },
                    condition: None,
                    on_success: Some("notify".to_string()),
                    on_failure: Some("notify".to_string()),
                    timeout_secs: 30,
                },
                PlaybookStep {
                    id: "notify".to_string(),
                    name: "Notify".to_string(),
                    action: PlaybookAction::SendEmail { 
                        recipients: vec!["security@example.com".to_string()],
                        template: "brute-force-blocked".to_string(),
                    },
                    condition: None,
                    on_success: None,
                    on_failure: None,
                    timeout_secs: 10,
                },
            ],
            enabled: true,
            timeout_secs: 120,
            created_at: chrono::Utc::now(),
        });
    }
    
    /// Register playbook
    pub fn register_playbook(&self, playbook: Playbook) {
        tracing::info!("Registering playbook: {} ({})", playbook.name, playbook.id);
        self.playbooks.insert(playbook.id.clone(), playbook);
    }
    
    /// Trigger playbooks for alert
    pub async fn trigger(&self, alert: &SecurityAlert) {
        let matching = self.find_matching_playbooks(alert);
        
        for playbook in matching {
            if !playbook.enabled {
                continue;
            }
            
            tracing::info!(
                "Triggering playbook {} for alert {}",
                playbook.name, alert.id
            );
            
            self.execute_playbook(&playbook, alert).await;
        }
    }
    
    fn find_matching_playbooks(&self, alert: &SecurityAlert) -> Vec<Playbook> {
        self.playbooks.iter()
            .filter(|p| self.trigger_matches(&p.trigger, alert))
            .map(|p| p.clone())
            .collect()
    }
    
    fn trigger_matches(&self, trigger: &PlaybookTrigger, alert: &SecurityAlert) -> bool {
        match trigger {
            PlaybookTrigger::AlertType(t) => &alert.alert_type == t,
            PlaybookTrigger::Severity(s) => alert.severity >= *s,
            PlaybookTrigger::MitreAttack { tactics, techniques } => {
                tactics.iter().any(|t| alert.mitre_tactics.contains(t)) ||
                techniques.iter().any(|t| alert.mitre_techniques.contains(t))
            }
            PlaybookTrigger::Manual => false,
            PlaybookTrigger::Schedule { .. } => false,
            PlaybookTrigger::Indicator { .. } => false,
        }
    }
    
    async fn execute_playbook(&self, playbook: &Playbook, alert: &SecurityAlert) {
        let mut execution = PlaybookExecution {
            id: uuid::Uuid::new_v4().to_string(),
            playbook_id: playbook.id.clone(),
            alert_id: alert.id.clone(),
            started_at: chrono::Utc::now(),
            ended_at: None,
            status: ExecutionStatus::Running,
            current_step: playbook.steps.first().map(|s| s.id.clone()),
            step_results: HashMap::new(),
            context: HashMap::new(),
        };
        
        // Add alert to context
        execution.context.insert(
            "alert".to_string(),
            serde_json::to_value(alert).unwrap_or_default()
        );
        
        self.executions.insert(execution.id.clone(), execution.clone());
        self.execution_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        // Execute steps
        let mut current_step_id = playbook.steps.first().map(|s| s.id.clone());
        
        while let Some(step_id) = current_step_id {
            let step = playbook.steps.iter()
                .find(|s| s.id == step_id);
            
            if let Some(step) = step {
                let result = self.execute_step(step, &mut execution.context).await;
                
                execution.step_results.insert(step.id.clone(), result.clone());
                
                current_step_id = match result.status {
                    StepStatus::Completed => step.on_success.clone(),
                    StepStatus::Failed => step.on_failure.clone(),
                    _ => None,
                };
            } else {
                break;
            }
        }
        
        execution.status = ExecutionStatus::Completed;
        execution.ended_at = Some(chrono::Utc::now());
        
        if let Some(mut e) = self.executions.get_mut(&execution.id) {
            *e = execution;
        }
    }
    
    async fn execute_step(
        &self,
        step: &PlaybookStep,
        context: &mut HashMap<String, serde_json::Value>,
    ) -> StepResult {
        let start = std::time::Instant::now();
        
        tracing::debug!("Executing step: {}", step.name);
        
        // Check condition
        if let Some(condition) = &step.condition {
            if !self.evaluate_condition(condition, context) {
                return StepResult {
                    step_id: step.id.clone(),
                    status: StepStatus::Skipped,
                    output: serde_json::Value::Null,
                    error: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        }
        
        // Execute action (placeholder - in production would call action handlers)
        let result = self.execute_action(&step.action, context).await;
        
        match result {
            Ok(output) => StepResult {
                step_id: step.id.clone(),
                status: StepStatus::Completed,
                output,
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => StepResult {
                step_id: step.id.clone(),
                status: StepStatus::Failed,
                output: serde_json::Value::Null,
                error: Some(e.to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }
    
    fn evaluate_condition(
        &self,
        condition: &StepCondition,
        context: &HashMap<String, serde_json::Value>,
    ) -> bool {
        let value = context.get(&condition.field);
        
        match condition.operator {
            ConditionOperator::Exists => value.is_some(),
            ConditionOperator::Equals => {
                value.map(|v| v.to_string() == condition.value).unwrap_or(false)
            }
            ConditionOperator::NotEquals => {
                value.map(|v| v.to_string() != condition.value).unwrap_or(true)
            }
            ConditionOperator::Contains => {
                value.map(|v| v.to_string().contains(&condition.value)).unwrap_or(false)
            }
            _ => true,
        }
    }
    
    async fn execute_action(
        &self,
        action: &PlaybookAction,
        context: &mut HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value, ActionError> {
        match action {
            PlaybookAction::Wait { seconds } => {
                tokio::time::sleep(tokio::time::Duration::from_secs(*seconds)).await;
                Ok(serde_json::json!({"waited": seconds}))
            }
            PlaybookAction::BlockIp { ip_field } => {
                let ip = context.get(ip_field)
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                tracing::info!("SOAR: Blocking IP {}", ip);
                Ok(serde_json::json!({"blocked_ip": ip}))
            }
            PlaybookAction::IsolateHost { host_field } => {
                let host = context.get(host_field)
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                tracing::info!("SOAR: Isolating host {}", host);
                Ok(serde_json::json!({"isolated_host": host}))
            }
            PlaybookAction::DisableUser { user_field } => {
                let user = context.get(user_field)
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                tracing::info!("SOAR: Disabling user {}", user);
                Ok(serde_json::json!({"disabled_user": user}))
            }
            PlaybookAction::SendSlack { channel, template } => {
                tracing::info!("SOAR: Sending Slack to {} (template: {})", channel, template);
                Ok(serde_json::json!({"sent_to": channel}))
            }
            PlaybookAction::SendEmail { recipients, template } => {
                tracing::info!("SOAR: Sending email to {:?} (template: {})", recipients, template);
                Ok(serde_json::json!({"sent_to": recipients}))
            }
            PlaybookAction::CreateCase { template } => {
                tracing::info!("SOAR: Creating case from template {}", template);
                let case_id = uuid::Uuid::new_v4().to_string();
                context.insert("case_id".to_string(), serde_json::json!(case_id));
                Ok(serde_json::json!({"case_id": case_id}))
            }
            _ => {
                Ok(serde_json::json!({"status": "executed"}))
            }
        }
    }
    
    /// Get execution count
    pub async fn get_execution_count(&self) -> u64 {
        self.execution_count.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    /// Get execution status
    pub fn get_execution(&self, id: &str) -> Option<PlaybookExecution> {
        self.executions.get(id).map(|e| e.clone())
    }
}

impl Default for SoarEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ActionError(String);

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ActionError {}
