//! URL Filter - Secure Web Gateway
//!
//! Categorizes URLs and enforces access policies.

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

proxy_wasm::main! {{
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(UrlFilterRoot::new())
    });
}}

/// URL filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlFilterConfig {
    /// Blocked URL categories
    #[serde(default)]
    pub blocked_categories: Vec<String>,
    
    /// Allowed URL categories
    #[serde(default)]
    pub allowed_categories: Vec<String>,
    
    /// Blocked domains (explicit)
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    
    /// Allowed domains (explicit whitelist)
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for UrlFilterConfig {
    fn default() -> Self {
        Self {
            blocked_categories: vec![
                "malware".to_string(),
                "phishing".to_string(),
                "gambling".to_string(),
            ],
            allowed_categories: vec![],
            blocked_domains: vec![],
            allowed_domains: vec![],
            log_level: "info".to_string(),
        }
    }
}

/// Root context for URL filter
pub struct UrlFilterRoot {
    config: UrlFilterConfig,
    blocked_domains_set: HashSet<String>,
    allowed_domains_set: HashSet<String>,
}

impl UrlFilterRoot {
    fn new() -> Self {
        Self {
            config: UrlFilterConfig::default(),
            blocked_domains_set: HashSet::new(),
            allowed_domains_set: HashSet::new(),
        }
    }
    
    /// Categorize a domain
    fn categorize_domain(&self, domain: &str) -> Option<&'static str> {
        // Known malware domains
        let malware_patterns = [
            "malware", "virus", "trojan", "exploit",
        ];
        
        // Known phishing patterns
        let phishing_patterns = [
            "login-", "secure-", "account-", "verify-", "update-",
        ];
        
        // Known adult content
        let adult_patterns = [
            "adult", "xxx", "porn",
        ];
        
        // Known gambling
        let gambling_patterns = [
            "casino", "poker", "betting", "slots",
        ];
        
        let domain_lower = domain.to_lowercase();
        
        for pattern in malware_patterns {
            if domain_lower.contains(pattern) {
                return Some("malware");
            }
        }
        
        for pattern in phishing_patterns {
            if domain_lower.starts_with(pattern) {
                return Some("phishing");
            }
        }
        
        for pattern in adult_patterns {
            if domain_lower.contains(pattern) {
                return Some("adult");
            }
        }
        
        for pattern in gambling_patterns {
            if domain_lower.contains(pattern) {
                return Some("gambling");
            }
        }
        
        // Business / Technology domains
        if domain_lower.ends_with(".com") || domain_lower.ends_with(".io") {
            return Some("business");
        }
        
        None
    }
}

impl Context for UrlFilterRoot {}

impl RootContext for UrlFilterRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(config) = serde_json::from_slice::<UrlFilterConfig>(&config_bytes) {
                self.config = config;
                
                // Build domain sets for fast lookup
                self.blocked_domains_set = self.config.blocked_domains
                    .iter()
                    .map(|d| d.to_lowercase())
                    .collect();
                    
                self.allowed_domains_set = self.config.allowed_domains
                    .iter()
                    .map(|d| d.to_lowercase())
                    .collect();
                    
                log::info!(
                    "URL filter configured: {} blocked categories, {} blocked domains",
                    self.config.blocked_categories.len(),
                    self.blocked_domains_set.len()
                );
            }
        }
        true
    }
    
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(UrlFilter {
            config: self.config.clone(),
            blocked_domains: self.blocked_domains_set.clone(),
            allowed_domains: self.allowed_domains_set.clone(),
        }))
    }
    
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// HTTP context for URL filter
pub struct UrlFilter {
    config: UrlFilterConfig,
    blocked_domains: HashSet<String>,
    allowed_domains: HashSet<String>,
}

impl Context for UrlFilter {}

impl HttpContext for UrlFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Get the host header
        let host = match self.get_http_request_header(":authority") {
            Some(h) => h,
            None => {
                log::warn!("No :authority header found");
                return Action::Continue;
            }
        };
        
        // Remove port if present
        let domain = host.split(':').next().unwrap_or(&host).to_lowercase();
        
        // Check explicit whitelist
        if self.allowed_domains.contains(&domain) {
            self.set_http_request_header("x-url-filter-result", Some("allowed"));
            return Action::Continue;
        }
        
        // Check explicit blocklist
        if self.blocked_domains.contains(&domain) {
            log::warn!("Blocked domain: {}", domain);
            self.send_http_response(
                403,
                vec![("content-type", "text/html")],
                Some(b"<html><body><h1>Access Denied</h1><p>This website is blocked by policy.</p></body></html>"),
            );
            return Action::Pause;
        }
        
        // Categorize and check
        if let Some(category) = self.categorize_domain(&domain) {
            if self.config.blocked_categories.iter().any(|c| c == category) {
                log::warn!("Blocked domain {} (category: {})", domain, category);
                self.send_http_response(
                    403,
                    vec![("content-type", "text/html")],
                    Some(format!(
                        "<html><body><h1>Access Denied</h1><p>This website ({}) is blocked. Category: {}</p></body></html>",
                        domain, category
                    ).as_bytes()),
                );
                return Action::Pause;
            }
            
            self.set_http_request_header("x-url-category", Some(category));
        }
        
        self.set_http_request_header("x-url-filter-result", Some("allowed"));
        Action::Continue
    }
}

impl UrlFilter {
    fn categorize_domain(&self, domain: &str) -> Option<&'static str> {
        // Known malware domains
        let malware_patterns = ["malware", "virus", "trojan", "exploit"];
        let phishing_patterns = ["login-", "secure-", "account-", "verify-"];
        let adult_patterns = ["adult", "xxx", "porn"];
        let gambling_patterns = ["casino", "poker", "betting", "slots"];
        
        let domain_lower = domain.to_lowercase();
        
        for pattern in malware_patterns {
            if domain_lower.contains(pattern) {
                return Some("malware");
            }
        }
        
        for pattern in phishing_patterns {
            if domain_lower.starts_with(pattern) {
                return Some("phishing");
            }
        }
        
        for pattern in adult_patterns {
            if domain_lower.contains(pattern) {
                return Some("adult");
            }
        }
        
        for pattern in gambling_patterns {
            if domain_lower.contains(pattern) {
                return Some("gambling");
            }
        }
        
        Some("business")
    }
}
