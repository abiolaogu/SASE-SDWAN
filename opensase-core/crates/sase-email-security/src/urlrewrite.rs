//! URL Rewriting and Scanning
//!
//! Safe URL rewriting through proxy for click-time analysis.

use crate::{EmailMessage, ExtractedUrl};
use std::collections::HashMap;

/// URL rewriter for safe link handling
pub struct UrlRewriter {
    /// Rewrite proxy base URL
    proxy_base: String,
    /// Encryption key for URL tokens
    token_key: [u8; 32],
    /// Bypass domains (internal/trusted)
    bypass_domains: std::collections::HashSet<String>,
}

impl UrlRewriter {
    pub fn new(proxy_base: &str, token_key: [u8; 32]) -> Self {
        Self {
            proxy_base: proxy_base.to_string(),
            token_key,
            bypass_domains: default_bypass_domains(),
        }
    }
    
    /// Rewrite all URLs in message
    pub fn rewrite_urls(&self, message: &mut EmailMessage) -> RewriteResult {
        let mut result = RewriteResult::default();
        
        // Rewrite URLs in body
        for url in &mut message.body.urls {
            if self.should_rewrite(&url.url) {
                let rewritten = self.create_safe_url(&url.url, &message.id);
                url.url = rewritten;
                result.urls_rewritten += 1;
            } else {
                result.urls_bypassed += 1;
            }
        }
        
        // Rewrite HTML if present
        if let Some(html) = &message.body.text_html {
            let rewritten_html = self.rewrite_html_urls(html, &message.id);
            message.body.text_html = Some(rewritten_html);
        }
        
        result
    }
    
    fn should_rewrite(&self, url: &str) -> bool {
        // Don't rewrite internal/trusted domains
        if let Some(domain) = extract_domain_from_url(url) {
            if self.bypass_domains.contains(&domain) {
                return false;
            }
        }
        
        // Don't rewrite mailto: or tel:
        if url.starts_with("mailto:") || url.starts_with("tel:") {
            return false;
        }
        
        // Rewrite http/https URLs
        url.starts_with("http://") || url.starts_with("https://")
    }
    
    fn create_safe_url(&self, original_url: &str, message_id: &str) -> String {
        // Create encrypted token
        let token = self.encrypt_url_token(original_url, message_id);
        
        format!("{}/click/{}", self.proxy_base, token)
    }
    
    fn encrypt_url_token(&self, url: &str, message_id: &str) -> String {
        // Simplified: would use proper AES-GCM encryption
        let payload = format!("{}|{}", message_id, url);
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload.as_bytes())
    }
    
    fn rewrite_html_urls(&self, html: &str, message_id: &str) -> String {
        // Simple regex-based rewrite
        let url_regex = regex::Regex::new(r#"href="(https?://[^"]+)""#).unwrap();
        
        url_regex.replace_all(html, |caps: &regex::Captures| {
            let original = &caps[1];
            if self.should_rewrite(original) {
                let safe_url = self.create_safe_url(original, message_id);
                format!(r#"href="{}""#, safe_url)
            } else {
                caps[0].to_string()
            }
        }).to_string()
    }
    
    /// Add bypass domain
    pub fn add_bypass_domain(&mut self, domain: &str) {
        self.bypass_domains.insert(domain.to_lowercase());
    }
}

#[derive(Debug, Default)]
pub struct RewriteResult {
    pub urls_rewritten: usize,
    pub urls_bypassed: usize,
}

/// Click-time URL scanner
pub struct ClickTimeScanner {
    /// Threat intel integration
    threat_intel: Option<std::sync::Arc<dyn ThreatIntelLookup>>,
    /// URL scanner
    url_scanner: UrlScanner,
}

pub trait ThreatIntelLookup: Send + Sync {
    fn check_url(&self, url: &str) -> Option<ThreatMatch>;
    fn check_domain(&self, domain: &str) -> Option<ThreatMatch>;
}

#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub is_malicious: bool,
    pub category: String,
    pub confidence: f64,
}

impl ClickTimeScanner {
    pub fn new() -> Self {
        Self {
            threat_intel: None,
            url_scanner: UrlScanner::new(),
        }
    }
    
    /// Scan URL at click time
    pub async fn scan(&self, token: &str) -> ClickResult {
        // Decrypt token to get original URL
        let original_url = match self.decrypt_token(token) {
            Ok(url) => url,
            Err(_) => return ClickResult::Block { reason: "Invalid token".to_string() },
        };
        
        // Check threat intel
        if let Some(ti) = &self.threat_intel {
            if let Some(threat) = ti.check_url(&original_url) {
                if threat.is_malicious {
                    return ClickResult::Block {
                        reason: format!("Malicious URL: {}", threat.category),
                    };
                }
            }
        }
        
        // Real-time URL scan
        let scan_result = self.url_scanner.scan(&original_url).await;
        
        if scan_result.is_malicious {
            ClickResult::Block { reason: scan_result.reason }
        } else if scan_result.is_suspicious {
            ClickResult::Warn {
                original_url,
                warning: scan_result.reason,
            }
        } else {
            ClickResult::Allow { original_url }
        }
    }
    
    fn decrypt_token(&self, token: &str) -> Result<String, &'static str> {
        // Simplified decryption
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token)
            .map_err(|_| "Invalid token encoding")?;
        
        let payload = String::from_utf8(decoded).map_err(|_| "Invalid token content")?;
        
        payload.split('|')
            .nth(1)
            .map(|s| s.to_string())
            .ok_or("Malformed token")
    }
}

impl Default for ClickTimeScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum ClickResult {
    Allow { original_url: String },
    Warn { original_url: String, warning: String },
    Block { reason: String },
}

struct UrlScanner;

impl UrlScanner {
    fn new() -> Self { Self }
    
    async fn scan(&self, _url: &str) -> UrlScanResult {
        // Would perform real-time URL scanning
        UrlScanResult {
            is_malicious: false,
            is_suspicious: false,
            reason: String::new(),
        }
    }
}

struct UrlScanResult {
    is_malicious: bool,
    is_suspicious: bool,
    reason: String,
}

fn extract_domain_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    
    without_scheme
        .split('/')
        .next()
        .map(|s| s.split(':').next().unwrap_or(s).to_lowercase())
}

fn default_bypass_domains() -> std::collections::HashSet<String> {
    std::collections::HashSet::new()
}

use base64::Engine as _;
