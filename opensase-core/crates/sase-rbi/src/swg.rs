//! SWG Integration
//!
//! Secure Web Gateway integration for isolation decisions.

use crate::policy::{UrlPolicy, UrlDecision, UrlCategory};
use std::net::IpAddr;

/// SWG-RBI integration for isolation decisions
pub struct SwgIntegration {
    /// URL policy engine
    url_policy: UrlPolicy,
    /// Isolation rules
    isolation_rules: IsolationRules,
    /// Statistics
    stats: SwgStats,
}

#[derive(Debug, Clone)]
pub struct IsolationRules {
    /// Always isolate these categories
    pub isolate_categories: Vec<UrlCategory>,
    /// Always isolate these domains
    pub isolate_domains: Vec<String>,
    /// Never isolate these domains (trusted)
    pub bypass_domains: Vec<String>,
    /// Isolate unknown/uncategorized sites
    pub isolate_uncategorized: bool,
    /// Isolate first visit to new domains
    pub isolate_first_visit: bool,
    /// Risk score threshold for isolation (0-100)
    pub risk_threshold: u32,
}

impl Default for IsolationRules {
    fn default() -> Self {
        Self {
            isolate_categories: vec![
                UrlCategory::Unknown,
                UrlCategory::Malware,
                UrlCategory::Phishing,
            ],
            isolate_domains: Vec::new(),
            bypass_domains: vec![
                "google.com".to_string(),
                "microsoft.com".to_string(),
                "github.com".to_string(),
                "amazonaws.com".to_string(),
            ],
            isolate_uncategorized: true,
            isolate_first_visit: false,
            risk_threshold: 50,
        }
    }
}

/// Isolation decision for a request
#[derive(Debug, Clone)]
pub enum IsolationDecision {
    /// Allow direct access
    Allow,
    /// Isolate in RBI container
    Isolate(IsolationReason),
    /// Block completely
    Block(String),
}

#[derive(Debug, Clone)]
pub enum IsolationReason {
    Category(UrlCategory),
    Domain,
    RiskScore(u32),
    Uncategorized,
    FirstVisit,
    UserPolicy,
    Manual,
}

#[derive(Debug, Default)]
struct SwgStats {
    requests_total: std::sync::atomic::AtomicU64,
    requests_allowed: std::sync::atomic::AtomicU64,
    requests_isolated: std::sync::atomic::AtomicU64,
    requests_blocked: std::sync::atomic::AtomicU64,
}

/// HTTP request for SWG analysis
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub user_id: String,
    pub source_ip: IpAddr,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
}

impl SwgIntegration {
    pub fn new(url_policy: UrlPolicy, isolation_rules: IsolationRules) -> Self {
        Self {
            url_policy,
            isolation_rules,
            stats: SwgStats::default(),
        }
    }
    
    /// Decide whether to isolate a request
    pub fn decide(&self, request: &HttpRequest) -> IsolationDecision {
        use std::sync::atomic::Ordering;
        
        self.stats.requests_total.fetch_add(1, Ordering::Relaxed);
        
        let domain = extract_domain(&request.url);
        
        // Check bypass list (trusted domains)
        if self.is_bypassed(&domain) {
            self.stats.requests_allowed.fetch_add(1, Ordering::Relaxed);
            return IsolationDecision::Allow;
        }
        
        // Check URL policy first
        match self.url_policy.check(&request.url) {
            UrlDecision::Block(reason) => {
                self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
                return IsolationDecision::Block(format!("{:?}", reason));
            }
            UrlDecision::Isolate => {
                self.stats.requests_isolated.fetch_add(1, Ordering::Relaxed);
                return IsolationDecision::Isolate(IsolationReason::UserPolicy);
            }
            _ => {}
        }
        
        // Check explicit isolation domains
        if self.isolation_rules.isolate_domains.iter()
            .any(|d| domain.ends_with(d)) {
            self.stats.requests_isolated.fetch_add(1, Ordering::Relaxed);
            return IsolationDecision::Isolate(IsolationReason::Domain);
        }
        
        // Check category-based isolation
        let category = self.categorize(&domain);
        if self.isolation_rules.isolate_categories.contains(&category) {
            self.stats.requests_isolated.fetch_add(1, Ordering::Relaxed);
            return IsolationDecision::Isolate(IsolationReason::Category(category));
        }
        
        // Check risk score
        let risk_score = self.calculate_risk(&request);
        if risk_score >= self.isolation_rules.risk_threshold {
            self.stats.requests_isolated.fetch_add(1, Ordering::Relaxed);
            return IsolationDecision::Isolate(IsolationReason::RiskScore(risk_score));
        }
        
        // Uncategorized handling
        if category == UrlCategory::Unknown && self.isolation_rules.isolate_uncategorized {
            self.stats.requests_isolated.fetch_add(1, Ordering::Relaxed);
            return IsolationDecision::Isolate(IsolationReason::Uncategorized);
        }
        
        self.stats.requests_allowed.fetch_add(1, Ordering::Relaxed);
        IsolationDecision::Allow
    }
    
    /// Force isolation for a domain
    pub fn add_isolation_domain(&mut self, domain: &str) {
        self.isolation_rules.isolate_domains.push(domain.to_lowercase());
    }
    
    /// Add trusted domain to bypass list
    pub fn add_bypass_domain(&mut self, domain: &str) {
        self.isolation_rules.bypass_domains.push(domain.to_lowercase());
    }
    
    fn is_bypassed(&self, domain: &str) -> bool {
        self.isolation_rules.bypass_domains.iter()
            .any(|d| domain == d || domain.ends_with(&format!(".{}", d)))
    }
    
    fn categorize(&self, _domain: &str) -> UrlCategory {
        // Would use threat intelligence/categorization service
        UrlCategory::Unknown
    }
    
    fn calculate_risk(&self, request: &HttpRequest) -> u32 {
        let mut score = 0u32;
        
        // New domain
        let domain = extract_domain(&request.url);
        if domain.len() > 30 {
            score += 10; // Long domains are suspicious
        }
        
        // Contains IP address
        if request.url.chars().filter(|c| *c == '.').count() >= 3 &&
           request.url.chars().all(|c| c.is_numeric() || c == '.' || c == '/' || c == ':') {
            score += 30;
        }
        
        // Suspicious TLDs
        let suspicious_tlds = [".xyz", ".top", ".gq", ".ml", ".tk", ".cf", ".ga"];
        if suspicious_tlds.iter().any(|t| domain.ends_with(t)) {
            score += 25;
        }
        
        // No referer on non-main page
        if request.referer.is_none() && request.url.contains('?') {
            score += 10;
        }
        
        score.min(100)
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> SwgSnapshot {
        use std::sync::atomic::Ordering;
        
        SwgSnapshot {
            requests_total: self.stats.requests_total.load(Ordering::Relaxed),
            requests_allowed: self.stats.requests_allowed.load(Ordering::Relaxed),
            requests_isolated: self.stats.requests_isolated.load(Ordering::Relaxed),
            requests_blocked: self.stats.requests_blocked.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SwgSnapshot {
    pub requests_total: u64,
    pub requests_allowed: u64,
    pub requests_isolated: u64,
    pub requests_blocked: u64,
}

fn extract_domain(url: &str) -> String {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bypass_domain() {
        let swg = SwgIntegration::new(
            UrlPolicy::default(),
            IsolationRules::default(),
        );
        
        let request = HttpRequest {
            url: "https://docs.google.com/document".to_string(),
            method: "GET".to_string(),
            user_id: "user-1".to_string(),
            source_ip: "10.0.0.1".parse().unwrap(),
            user_agent: None,
            referer: None,
        };
        
        assert!(matches!(swg.decide(&request), IsolationDecision::Allow));
    }
}
