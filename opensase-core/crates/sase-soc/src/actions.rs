//! SOAR Action Handlers
//!
//! Built-in handlers for playbook actions.

use crate::edr::EdrIntegration;
use std::sync::Arc;
use std::collections::HashMap;

#[async_trait::async_trait]
pub trait ActionHandler: Send + Sync {
    fn action_type(&self) -> &str;
    async fn execute(&self, params: &ActionParams) -> Result<ActionResult, ActionError>;
}

#[derive(Clone)]
pub struct ActionParams {
    pub context: HashMap<String, serde_json::Value>,
    pub action_config: HashMap<String, String>,
}

#[derive(Clone, serde::Serialize)]
pub struct ActionResult {
    pub success: bool,
    pub output: serde_json::Value,
    pub duration_ms: u64,
}

// Block IP Handler
pub struct BlockIpHandler {
    firewall_api: String,
    api_key: String,
    client: reqwest::Client,
}

impl BlockIpHandler {
    pub fn new(firewall_api: &str, api_key: &str) -> Self {
        Self {
            firewall_api: firewall_api.to_string(),
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ActionHandler for BlockIpHandler {
    fn action_type(&self) -> &str { "block_ip" }
    
    async fn execute(&self, params: &ActionParams) -> Result<ActionResult, ActionError> {
        let ip = params.context.get("source_ip")
            .and_then(|v| v.as_str())
            .ok_or(ActionError::MissingParam("source_ip".to_string()))?;
        
        let duration = params.action_config.get("duration")
            .and_then(|d| d.parse::<u64>().ok())
            .unwrap_or(3600);
        
        tracing::info!("Blocking IP {} for {} seconds", ip, duration);
        
        let start = std::time::Instant::now();
        
        // Call firewall API
        let _resp = self.client
            .post(&format!("{}/block", self.firewall_api))
            .header("X-API-Key", &self.api_key)
            .json(&serde_json::json!({
                "ip": ip,
                "duration": duration,
                "reason": "OpenSASE SOAR automated block"
            }))
            .send()
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;
        
        Ok(ActionResult {
            success: true,
            output: serde_json::json!({
                "action": "block_ip",
                "ip": ip,
                "duration": duration,
            }),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

// Isolate Device Handler
pub struct IsolateDeviceHandler {
    edr: Arc<dyn EdrIntegration>,
}

impl IsolateDeviceHandler {
    pub fn new(edr: Arc<dyn EdrIntegration>) -> Self {
        Self { edr }
    }
}

#[async_trait::async_trait]
impl ActionHandler for IsolateDeviceHandler {
    fn action_type(&self) -> &str { "isolate_device" }
    
    async fn execute(&self, params: &ActionParams) -> Result<ActionResult, ActionError> {
        let device_id = params.context.get("device_id")
            .and_then(|v| v.as_str())
            .ok_or(ActionError::MissingParam("device_id".to_string()))?;
        
        tracing::info!("Isolating device {} via {}", device_id, self.edr.name());
        
        let start = std::time::Instant::now();
        
        self.edr.isolate_device(device_id).await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;
        
        Ok(ActionResult {
            success: true,
            output: serde_json::json!({
                "action": "isolate_device",
                "device_id": device_id,
                "edr": self.edr.name(),
            }),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

// Disable User Handler
pub struct DisableUserHandler {
    idp_api: String,
    api_key: String,
    client: reqwest::Client,
}

impl DisableUserHandler {
    pub fn new(idp_api: &str, api_key: &str) -> Self {
        Self {
            idp_api: idp_api.to_string(),
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ActionHandler for DisableUserHandler {
    fn action_type(&self) -> &str { "disable_user" }
    
    async fn execute(&self, params: &ActionParams) -> Result<ActionResult, ActionError> {
        let user_id = params.context.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or(ActionError::MissingParam("user_id".to_string()))?;
        
        tracing::info!("Disabling user {}", user_id);
        
        let start = std::time::Instant::now();
        
        let _resp = self.client
            .post(&format!("{}/users/{}/disable", self.idp_api, user_id))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;
        
        Ok(ActionResult {
            success: true,
            output: serde_json::json!({
                "action": "disable_user",
                "user_id": user_id,
            }),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

// Send Slack Handler
pub struct SendSlackHandler {
    webhook_url: String,
    client: reqwest::Client,
}

impl SendSlackHandler {
    pub fn new(webhook_url: &str) -> Self {
        Self {
            webhook_url: webhook_url.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ActionHandler for SendSlackHandler {
    fn action_type(&self) -> &str { "send_slack" }
    
    async fn execute(&self, params: &ActionParams) -> Result<ActionResult, ActionError> {
        let channel = params.action_config.get("channel")
            .ok_or(ActionError::MissingParam("channel".to_string()))?;
        
        let message = params.action_config.get("message")
            .ok_or(ActionError::MissingParam("message".to_string()))?;
        
        let start = std::time::Instant::now();
        
        let _resp = self.client
            .post(&self.webhook_url)
            .json(&serde_json::json!({
                "channel": channel,
                "text": message,
                "username": "OpenSASE SOAR",
            }))
            .send()
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;
        
        Ok(ActionResult {
            success: true,
            output: serde_json::json!({
                "action": "send_slack",
                "channel": channel,
            }),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

// Create Ticket Handler
pub struct CreateTicketHandler {
    jira_url: String,
    api_token: String,
    project_key: String,
    client: reqwest::Client,
}

impl CreateTicketHandler {
    pub fn new(jira_url: &str, api_token: &str, project_key: &str) -> Self {
        Self {
            jira_url: jira_url.to_string(),
            api_token: api_token.to_string(),
            project_key: project_key.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ActionHandler for CreateTicketHandler {
    fn action_type(&self) -> &str { "create_ticket" }
    
    async fn execute(&self, params: &ActionParams) -> Result<ActionResult, ActionError> {
        let summary = params.action_config.get("summary")
            .ok_or(ActionError::MissingParam("summary".to_string()))?;
        
        let description = params.action_config.get("description")
            .unwrap_or(&"Security incident".to_string())
            .clone();
        
        let start = std::time::Instant::now();
        
        let resp = self.client
            .post(&format!("{}/rest/api/3/issue", self.jira_url))
            .header("Authorization", format!("Basic {}", self.api_token))
            .json(&serde_json::json!({
                "fields": {
                    "project": { "key": self.project_key },
                    "summary": summary,
                    "description": description,
                    "issuetype": { "name": "Bug" }
                }
            }))
            .send()
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;
        
        let data: serde_json::Value = resp.json().await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;
        
        let ticket_id = data["key"].as_str().unwrap_or("unknown");
        
        Ok(ActionResult {
            success: true,
            output: serde_json::json!({
                "action": "create_ticket",
                "ticket_id": ticket_id,
            }),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

// Page On-Call Handler
pub struct PageOnCallHandler {
    pagerduty_key: String,
    client: reqwest::Client,
}

impl PageOnCallHandler {
    pub fn new(pagerduty_key: &str) -> Self {
        Self {
            pagerduty_key: pagerduty_key.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ActionHandler for PageOnCallHandler {
    fn action_type(&self) -> &str { "page_oncall" }
    
    async fn execute(&self, params: &ActionParams) -> Result<ActionResult, ActionError> {
        let team = params.action_config.get("team")
            .ok_or(ActionError::MissingParam("team".to_string()))?;
        
        let message = params.action_config.get("message")
            .ok_or(ActionError::MissingParam("message".to_string()))?;
        
        let start = std::time::Instant::now();
        
        let _resp = self.client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&serde_json::json!({
                "routing_key": self.pagerduty_key,
                "event_action": "trigger",
                "payload": {
                    "summary": message,
                    "severity": "critical",
                    "source": "OpenSASE SOAR",
                    "custom_details": {
                        "team": team
                    }
                }
            }))
            .send()
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;
        
        Ok(ActionResult {
            success: true,
            output: serde_json::json!({
                "action": "page_oncall",
                "team": team,
            }),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[derive(Debug)]
pub enum ActionError {
    MissingParam(String),
    ExecutionFailed(String),
    Timeout,
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingParam(p) => write!(f, "Missing param: {}", p),
            Self::ExecutionFailed(e) => write!(f, "Execution failed: {}", e),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for ActionError {}
