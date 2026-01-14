//! SIEM Integration
//!
//! Connectors for Splunk, Elastic, Sentinel, QRadar.

use crate::{SecurityEvent, SecurityAlert, Severity};
use async_trait::async_trait;

/// SIEM integration hub
pub struct SiemIntegration {
    /// Available connectors
    connectors: dashmap::DashMap<String, Box<dyn SiemConnector>>,
    /// Event buffer
    event_buffer: dashmap::DashMap<String, Vec<SecurityEvent>>,
    /// Stats
    stats: SiemStats,
}

struct SiemStats {
    events_forwarded: std::sync::atomic::AtomicU64,
    events_failed: std::sync::atomic::AtomicU64,
}

#[async_trait]
pub trait SiemConnector: Send + Sync {
    fn name(&self) -> &str;
    async fn send_event(&self, event: &SecurityEvent) -> Result<(), SiemError>;
    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<(), SiemError>;
    async fn query(&self, query: &str, time_range: TimeRange) -> Result<Vec<serde_json::Value>, SiemError>;
    async fn health_check(&self) -> bool;
}

#[derive(Clone)]
pub struct TimeRange {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

// =============================================================================
// Splunk Connector
// =============================================================================

pub struct SplunkConnector {
    config: SplunkConfig,
    client: reqwest::Client,
}

#[derive(Clone)]
pub struct SplunkConfig {
    pub host: String,
    pub port: u16,
    pub token: String,
    pub index: String,
    pub source_type: String,
    pub ssl_verify: bool,
}

impl SplunkConnector {
    pub fn new(config: SplunkConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SiemConnector for SplunkConnector {
    fn name(&self) -> &str {
        "splunk"
    }
    
    async fn send_event(&self, event: &SecurityEvent) -> Result<(), SiemError> {
        let url = format!(
            "{}:{}/services/collector/event",
            self.config.host, self.config.port
        );
        
        let payload = serde_json::json!({
            "index": self.config.index,
            "sourcetype": self.config.source_type,
            "event": event,
        });
        
        let _response = self.client
            .post(&url)
            .header("Authorization", format!("Splunk {}", self.config.token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| SiemError::ConnectionFailed(e.to_string()))?;
        
        tracing::debug!("Sent event {} to Splunk", event.id);
        Ok(())
    }
    
    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<(), SiemError> {
        for event in events {
            self.send_event(event).await?;
        }
        Ok(())
    }
    
    async fn query(&self, query: &str, time_range: TimeRange) -> Result<Vec<serde_json::Value>, SiemError> {
        let url = format!(
            "{}:{}/services/search/jobs/export",
            self.config.host, self.config.port
        );
        
        let search = format!(
            "search {} earliest={} latest={}",
            query,
            time_range.start.timestamp(),
            time_range.end.timestamp()
        );
        
        tracing::debug!("Executing Splunk query: {}", search);
        
        // In production: execute query and parse results
        Ok(vec![])
    }
    
    async fn health_check(&self) -> bool {
        true // In production: check Splunk health endpoint
    }
}

// =============================================================================
// Elastic Connector
// =============================================================================

pub struct ElasticConnector {
    config: ElasticConfig,
    client: reqwest::Client,
}

#[derive(Clone)]
pub struct ElasticConfig {
    pub hosts: Vec<String>,
    pub index_pattern: String,
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ssl_verify: bool,
}

impl ElasticConnector {
    pub fn new(config: ElasticConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SiemConnector for ElasticConnector {
    fn name(&self) -> &str {
        "elastic"
    }
    
    async fn send_event(&self, event: &SecurityEvent) -> Result<(), SiemError> {
        let host = self.config.hosts.first()
            .ok_or_else(|| SiemError::ConfigError("No hosts configured".to_string()))?;
        
        let index = format!("{}-{}", 
            self.config.index_pattern,
            chrono::Utc::now().format("%Y.%m.%d")
        );
        
        let url = format!("{}/_doc", host);
        
        let mut request = self.client.post(&url);
        
        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("ApiKey {}", api_key));
        }
        
        let _response = request
            .json(event)
            .send()
            .await
            .map_err(|e| SiemError::ConnectionFailed(e.to_string()))?;
        
        tracing::debug!("Sent event {} to Elastic index {}", event.id, index);
        Ok(())
    }
    
    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<(), SiemError> {
        // Use bulk API
        let host = self.config.hosts.first()
            .ok_or_else(|| SiemError::ConfigError("No hosts configured".to_string()))?;
        
        let url = format!("{}/_bulk", host);
        
        let mut bulk_body = String::new();
        for event in events {
            bulk_body.push_str(&serde_json::json!({"index": {}}).to_string());
            bulk_body.push('\n');
            bulk_body.push_str(&serde_json::to_string(event).unwrap());
            bulk_body.push('\n');
        }
        
        let _response = self.client
            .post(&url)
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_body)
            .send()
            .await
            .map_err(|e| SiemError::ConnectionFailed(e.to_string()))?;
        
        Ok(())
    }
    
    async fn query(&self, query: &str, time_range: TimeRange) -> Result<Vec<serde_json::Value>, SiemError> {
        let host = self.config.hosts.first()
            .ok_or_else(|| SiemError::ConfigError("No hosts configured".to_string()))?;
        
        let url = format!("{}/_search", host);
        
        let body = serde_json::json!({
            "query": {
                "bool": {
                    "must": [
                        { "query_string": { "query": query } }
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_range.start.to_rfc3339(),
                                    "lte": time_range.end.to_rfc3339()
                                }
                            }
                        }
                    ]
                }
            }
        });
        
        tracing::debug!("Executing Elastic query");
        
        // In production: execute and parse
        Ok(vec![])
    }
    
    async fn health_check(&self) -> bool {
        true // In production: check cluster health
    }
}

// =============================================================================
// Microsoft Sentinel Connector
// =============================================================================

pub struct SentinelConnector {
    config: SentinelConfig,
    client: reqwest::Client,
}

#[derive(Clone)]
pub struct SentinelConfig {
    pub workspace_id: String,
    pub shared_key: String,
    pub log_type: String,
    pub azure_resource_id: Option<String>,
}

impl SentinelConnector {
    pub fn new(config: SentinelConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
    
    fn build_signature(&self, date: &str, content_length: usize) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        let string_to_hash = format!(
            "POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs",
            content_length, date
        );
        
        let decoded_key = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.config.shared_key
        ).unwrap_or_default();
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&decoded_key).unwrap();
        mac.update(string_to_hash.as_bytes());
        let signature = mac.finalize().into_bytes();
        
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signature)
    }
}

#[async_trait]
impl SiemConnector for SentinelConnector {
    fn name(&self) -> &str {
        "sentinel"
    }
    
    async fn send_event(&self, event: &SecurityEvent) -> Result<(), SiemError> {
        let url = format!(
            "https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            self.config.workspace_id
        );
        
        let body = serde_json::to_string(&[event])
            .map_err(|e| SiemError::SerializationError(e.to_string()))?;
        
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let signature = self.build_signature(&date, body.len());
        
        let _response = self.client
            .post(&url)
            .header("Log-Type", &self.config.log_type)
            .header("x-ms-date", &date)
            .header("Authorization", format!("SharedKey {}:{}", self.config.workspace_id, signature))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| SiemError::ConnectionFailed(e.to_string()))?;
        
        tracing::debug!("Sent event {} to Sentinel", event.id);
        Ok(())
    }
    
    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<(), SiemError> {
        let url = format!(
            "https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            self.config.workspace_id
        );
        
        let body = serde_json::to_string(events)
            .map_err(|e| SiemError::SerializationError(e.to_string()))?;
        
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let signature = self.build_signature(&date, body.len());
        
        let _response = self.client
            .post(&url)
            .header("Log-Type", &self.config.log_type)
            .header("x-ms-date", &date)
            .header("Authorization", format!("SharedKey {}:{}", self.config.workspace_id, signature))
            .body(body)
            .send()
            .await
            .map_err(|e| SiemError::ConnectionFailed(e.to_string()))?;
        
        Ok(())
    }
    
    async fn query(&self, query: &str, time_range: TimeRange) -> Result<Vec<serde_json::Value>, SiemError> {
        // Use Log Analytics query API
        tracing::debug!("Executing Sentinel KQL query: {}", query);
        Ok(vec![])
    }
    
    async fn health_check(&self) -> bool {
        true
    }
}

// =============================================================================
// QRadar Connector
// =============================================================================

pub struct QRadarConnector {
    config: QRadarConfig,
    client: reqwest::Client,
}

#[derive(Clone)]
pub struct QRadarConfig {
    pub host: String,
    pub api_token: String,
    pub log_source_id: String,
    pub ssl_verify: bool,
}

impl QRadarConnector {
    pub fn new(config: QRadarConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SiemConnector for QRadarConnector {
    fn name(&self) -> &str {
        "qradar"
    }
    
    async fn send_event(&self, event: &SecurityEvent) -> Result<(), SiemError> {
        // QRadar uses syslog or REST API
        let url = format!("{}/api/siem/events", self.config.host);
        
        let _response = self.client
            .post(&url)
            .header("SEC", &self.config.api_token)
            .json(event)
            .send()
            .await
            .map_err(|e| SiemError::ConnectionFailed(e.to_string()))?;
        
        tracing::debug!("Sent event {} to QRadar", event.id);
        Ok(())
    }
    
    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<(), SiemError> {
        for event in events {
            self.send_event(event).await?;
        }
        Ok(())
    }
    
    async fn query(&self, query: &str, time_range: TimeRange) -> Result<Vec<serde_json::Value>, SiemError> {
        // Use AQL query
        let url = format!("{}/api/ariel/searches", self.config.host);
        
        tracing::debug!("Executing QRadar AQL: {}", query);
        // In production: execute AQL query
        Ok(vec![])
    }
    
    async fn health_check(&self) -> bool {
        true
    }
}

// =============================================================================
// SIEM Integration Implementation
// =============================================================================

impl SiemIntegration {
    pub fn new() -> Self {
        Self {
            connectors: dashmap::DashMap::new(),
            event_buffer: dashmap::DashMap::new(),
            stats: SiemStats {
                events_forwarded: std::sync::atomic::AtomicU64::new(0),
                events_failed: std::sync::atomic::AtomicU64::new(0),
            },
        }
    }
    
    /// Register connector
    pub fn register(&self, connector: Box<dyn SiemConnector>) {
        let name = connector.name().to_string();
        tracing::info!("Registering SIEM connector: {}", name);
        self.connectors.insert(name, connector);
    }
    
    /// Forward event to all SIEMs
    pub async fn forward(&self, event: &SecurityEvent) {
        for connector in self.connectors.iter() {
            match connector.send_event(event).await {
                Ok(_) => {
                    self.stats.events_forwarded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => {
                    self.stats.events_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!("Failed to send to {}: {}", connector.name(), e);
                }
            }
        }
    }
    
    /// Query a specific SIEM
    pub async fn query(&self, siem: &str, query: &str, time_range: TimeRange) -> Result<Vec<serde_json::Value>, SiemError> {
        let connector = self.connectors.get(siem)
            .ok_or_else(|| SiemError::NotFound(siem.to_string()))?;
        connector.query(query, time_range).await
    }
    
    /// Get event count
    pub async fn get_event_count(&self) -> u64 {
        self.stats.events_forwarded.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for SiemIntegration {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum SiemError {
    ConnectionFailed(String),
    ConfigError(String),
    QueryError(String),
    SerializationError(String),
    NotFound(String),
}

impl std::fmt::Display for SiemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            Self::ConfigError(e) => write!(f, "Config error: {}", e),
            Self::QueryError(e) => write!(f, "Query error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::NotFound(e) => write!(f, "Not found: {}", e),
        }
    }
}

impl std::error::Error for SiemError {}

use base64::Engine;
