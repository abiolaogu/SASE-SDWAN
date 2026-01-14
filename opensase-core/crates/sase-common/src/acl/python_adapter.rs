//! Python Component Adapter (ACL)
//!
//! Translates between Rust domain model and legacy Python services.
//! This is part of the Strangler Fig pattern for incremental modernization.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Python UPO adapter
/// 
/// Wraps calls to the legacy Python UPO component,
/// translating between domain models.
pub struct PythonUpoAdapter {
    base_url: String,
    client: HttpClient,
}

impl PythonUpoAdapter {
    /// Create adapter pointing to Python UPO service
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: HttpClient::new(Duration::from_secs(5)),
        }
    }

    /// Compile policy using legacy Python compiler
    /// 
    /// Translates domain PolicyAggregate to Python format,
    /// calls Python service, translates response back.
    pub async fn compile_policy(
        &self,
        policy_yaml: &str,
    ) -> Result<LegacyCompileResult, AdapterError> {
        let request = LegacyCompileRequest {
            policy: policy_yaml.to_string(),
            format: "yaml".to_string(),
        };

        let response = self.client
            .post(&format!("{}/compile", self.base_url), &request)
            .await?;

        Ok(response)
    }

    /// Apply policy using legacy Python adapters
    pub async fn apply_policy(
        &self,
        target: &str,
        config: &str,
    ) -> Result<LegacyApplyResult, AdapterError> {
        let request = LegacyApplyRequest {
            target: target.to_string(),
            config: config.to_string(),
        };

        let response = self.client
            .post(&format!("{}/apply", self.base_url), &request)
            .await?;

        Ok(response)
    }
}

/// Python QoE Selector adapter
pub struct PythonQoEAdapter {
    base_url: String,
    client: HttpClient,
}

impl PythonQoEAdapter {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: HttpClient::new(Duration::from_secs(5)),
        }
    }

    /// Get recommendation from Python QoE selector
    /// 
    /// Note: This is a fallback when Rust selector is not available.
    /// As modernization progresses, this should be deprecated.
    #[deprecated(note = "Use sase_path::PathSelector instead")]
    pub async fn get_recommendation(
        &self,
        site: &str,
        app_class: &str,
    ) -> Result<LegacyRecommendation, AdapterError> {
        let url = format!(
            "{}/recommend?site={}&app_class={}",
            self.base_url, site, app_class
        );
        self.client.get(&url).await
    }
}

/// Python DLP adapter
pub struct PythonDlpAdapter {
    base_url: String,
    client: HttpClient,
}

impl PythonDlpAdapter {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: HttpClient::new(Duration::from_secs(10)),
        }
    }

    /// Scan content using Python DLP
    /// 
    /// Note: This is ~1000x slower than Rust scanner.
    /// Use only for complex NLP-based classifiers not yet ported.
    #[deprecated(note = "Use sase_dlp::DLPScanner for 1000x better performance")]
    pub async fn scan(&self, content: &str) -> Result<LegacyScanResult, AdapterError> {
        let request = LegacyScanRequest {
            content: content.to_string(),
        };
        self.client.post(&format!("{}/scan", self.base_url), &request).await
    }
}

// === Legacy DTOs ===

#[derive(Debug, Serialize)]
struct LegacyCompileRequest {
    policy: String,
    format: String,
}

#[derive(Debug, Deserialize)]
pub struct LegacyCompileResult {
    pub success: bool,
    pub outputs: Vec<LegacyOutput>,
    pub errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LegacyOutput {
    pub target: String,
    pub content: String,
    pub format: String,
}

#[derive(Debug, Serialize)]
struct LegacyApplyRequest {
    target: String,
    config: String,
}

#[derive(Debug, Deserialize)]
pub struct LegacyApplyResult {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct LegacyRecommendation {
    pub primary: String,
    pub backup: Option<String>,
    pub score: f32,
    pub confidence: f32,
}

#[derive(Debug, Serialize)]
struct LegacyScanRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
pub struct LegacyScanResult {
    pub has_matches: bool,
    pub matches: Vec<LegacyMatch>,
    pub highest_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LegacyMatch {
    pub classifier: String,
    pub severity: String,
    pub location: String,
}

// === Adapter Error ===

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("connection error: {0}")]
    Connection(String),
    
    #[error("timeout")]
    Timeout,
    
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    
    #[error("legacy service error: {0}")]
    ServiceError(String),
}

// === HTTP Client (minimal implementation) ===

struct HttpClient {
    timeout: Duration,
}

impl HttpClient {
    fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        _url: &str,
        _body: &T,
    ) -> Result<R, AdapterError> {
        // In production, use reqwest or similar
        // This is a placeholder for the ACL structure
        Err(AdapterError::Connection(
            "HTTP client not implemented - use production HTTP library".into()
        ))
    }

    async fn get<R: for<'de> Deserialize<'de>>(
        &self,
        _url: &str,
    ) -> Result<R, AdapterError> {
        Err(AdapterError::Connection(
            "HTTP client not implemented - use production HTTP library".into()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_creation() {
        let upo = PythonUpoAdapter::new("http://localhost:8001");
        assert!(upo.base_url.contains("8001"));

        let qoe = PythonQoEAdapter::new("http://localhost:8002");
        assert!(qoe.base_url.contains("8002"));

        let dlp = PythonDlpAdapter::new("http://localhost:8003");
        assert!(dlp.base_url.contains("8003"));
    }
}
