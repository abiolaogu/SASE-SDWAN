//! DLP Filter - Data Loss Prevention
//!
//! Scans HTTP request/response bodies for sensitive data patterns.

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use regex::Regex;

proxy_wasm::main! {{
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(DlpFilterRoot::new())
    });
}}

/// DLP pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DlpPatternType {
    SSN,
    CreditCard,
    ApiKey,
    AwsKey,
    PrivateKey,
    Email,
    PhoneNumber,
    Custom(String),
}

/// DLP action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DlpAction {
    Block,
    Redact,
    Alert,
    Log,
}

/// DLP filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpFilterConfig {
    /// Enable DLP inspection
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Patterns to detect
    #[serde(default)]
    pub patterns: Vec<String>,
    
    /// Action on detection
    #[serde(default = "default_action")]
    pub action: DlpAction,
    
    /// Max body size to scan (bytes)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    
    /// Scan request bodies
    #[serde(default = "default_true")]
    pub scan_request: bool,
    
    /// Scan response bodies
    #[serde(default = "default_true")]
    pub scan_response: bool,
}

fn default_true() -> bool { true }
fn default_action() -> DlpAction { DlpAction::Block }
fn default_max_body_size() -> usize { 10 * 1024 * 1024 } // 10MB

impl Default for DlpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            patterns: vec![
                "SSN".to_string(),
                "CREDIT_CARD".to_string(),
                "API_KEY".to_string(),
            ],
            action: DlpAction::Block,
            max_body_size: 10 * 1024 * 1024,
            scan_request: true,
            scan_response: true,
        }
    }
}

/// Compiled DLP pattern
struct CompiledPattern {
    name: String,
    regex: Regex,
}

/// Root context for DLP filter
pub struct DlpFilterRoot {
    config: DlpFilterConfig,
    patterns: Vec<CompiledPattern>,
}

impl DlpFilterRoot {
    fn new() -> Self {
        Self {
            config: DlpFilterConfig::default(),
            patterns: Vec::new(),
        }
    }
    
    /// Compile patterns
    fn compile_patterns(&mut self) {
        self.patterns.clear();
        
        for pattern_name in &self.config.patterns {
            let regex_str = match pattern_name.as_str() {
                "SSN" => r"\b\d{3}-\d{2}-\d{4}\b",
                "CREDIT_CARD" => r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
                "API_KEY" => r"\b[A-Za-z0-9_-]{32,64}\b",
                "AWS_KEY" => r"\bAKIA[0-9A-Z]{16}\b",
                "PRIVATE_KEY" => r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
                "EMAIL" => r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "PHONE" => r"\b(?:\+1)?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
                custom => custom, // Use as-is for custom regex
            };
            
            if let Ok(regex) = Regex::new(regex_str) {
                self.patterns.push(CompiledPattern {
                    name: pattern_name.clone(),
                    regex,
                });
            } else {
                log::warn!("Failed to compile DLP pattern: {}", pattern_name);
            }
        }
        
        log::info!("DLP filter: compiled {} patterns", self.patterns.len());
    }
}

impl Context for DlpFilterRoot {}

impl RootContext for DlpFilterRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(config) = serde_json::from_slice::<DlpFilterConfig>(&config_bytes) {
                self.config = config;
                self.compile_patterns();
            }
        } else {
            self.compile_patterns();
        }
        true
    }
    
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(DlpFilter {
            config: self.config.clone(),
            patterns: self.patterns.iter().map(|p| CompiledPattern {
                name: p.name.clone(),
                regex: p.regex.clone(),
            }).collect(),
            request_body: Vec::new(),
            response_body: Vec::new(),
        }))
    }
    
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// HTTP context for DLP filter
pub struct DlpFilter {
    config: DlpFilterConfig,
    patterns: Vec<CompiledPattern>,
    request_body: Vec<u8>,
    response_body: Vec<u8>,
}

impl DlpFilter {
    /// Scan content for DLP violations
    fn scan_content(&self, content: &[u8]) -> Vec<String> {
        let mut violations = Vec::new();
        
        if let Ok(text) = std::str::from_utf8(content) {
            for pattern in &self.patterns {
                if pattern.regex.is_match(text) {
                    violations.push(pattern.name.clone());
                }
            }
        }
        
        violations
    }
    
    /// Handle detected violations
    fn handle_violations(&self, violations: &[String], direction: &str) -> Action {
        if violations.is_empty() {
            return Action::Continue;
        }
        
        log::warn!(
            "DLP violation detected in {}: {:?}",
            direction,
            violations
        );
        
        match self.config.action {
            DlpAction::Block => {
                self.send_http_response(
                    403,
                    vec![("content-type", "text/html")],
                    Some(format!(
                        "<html><body><h1>Data Loss Prevention</h1>\
                         <p>Sensitive data detected: {}</p>\
                         <p>This request has been blocked.</p></body></html>",
                        violations.join(", ")
                    ).as_bytes()),
                );
                Action::Pause
            }
            DlpAction::Redact => {
                // In real implementation, would redact the content
                self.set_http_request_header("x-dlp-redacted", Some("true"));
                Action::Continue
            }
            DlpAction::Alert | DlpAction::Log => {
                self.set_http_request_header(
                    "x-dlp-alert",
                    Some(&violations.join(","))
                );
                Action::Continue
            }
        }
    }
}

impl Context for DlpFilter {}

impl HttpContext for DlpFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if !self.config.enabled || !self.config.scan_request {
            return Action::Continue;
        }
        
        // Check content-length for body inspection
        if let Some(content_length) = self.get_http_request_header("content-length") {
            if let Ok(len) = content_length.parse::<usize>() {
                if len > self.config.max_body_size {
                    log::debug!("Request body too large for DLP scan: {} bytes", len);
                    return Action::Continue;
                }
            }
        }
        
        Action::Continue
    }
    
    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !self.config.enabled || !self.config.scan_request {
            return Action::Continue;
        }
        
        // Accumulate body
        if let Some(body) = self.get_http_request_body(0, body_size) {
            self.request_body.extend_from_slice(&body);
        }
        
        // Check size limit
        if self.request_body.len() > self.config.max_body_size {
            self.request_body.clear();
            return Action::Continue;
        }
        
        // Scan when complete
        if end_of_stream && !self.request_body.is_empty() {
            let violations = self.scan_content(&self.request_body);
            return self.handle_violations(&violations, "request");
        }
        
        Action::Continue
    }
    
    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if !self.config.enabled || !self.config.scan_response {
            return Action::Continue;
        }
        
        Action::Continue
    }
    
    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !self.config.enabled || !self.config.scan_response {
            return Action::Continue;
        }
        
        // Accumulate body
        if let Some(body) = self.get_http_response_body(0, body_size) {
            self.response_body.extend_from_slice(&body);
        }
        
        // Check size limit
        if self.response_body.len() > self.config.max_body_size {
            self.response_body.clear();
            return Action::Continue;
        }
        
        // Scan when complete
        if end_of_stream && !self.response_body.is_empty() {
            let violations = self.scan_content(&self.response_body);
            if !violations.is_empty() {
                log::warn!("DLP violation in response: {:?}", violations);
                self.set_http_response_header(
                    "x-dlp-alert-response",
                    Some(&violations.join(","))
                );
            }
        }
        
        Action::Continue
    }
}
