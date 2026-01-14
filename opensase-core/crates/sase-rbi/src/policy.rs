//! Policy Engine
//!
//! URL filtering, DLP, and access control for browser isolation.

use std::collections::HashSet;
use std::net::IpAddr;

/// URL filtering policy
pub struct UrlPolicy {
    /// Allowed domains (whitelist mode)
    allowed_domains: HashSet<String>,
    /// Blocked domains
    blocked_domains: HashSet<String>,
    /// Blocked URL patterns
    blocked_patterns: Vec<String>,
    /// Allowed URL categories
    allowed_categories: HashSet<UrlCategory>,
    /// Policy mode
    mode: PolicyMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    /// Block only explicit blocked domains
    Blacklist,
    /// Allow only explicit allowed domains
    Whitelist,
    /// Category-based filtering
    Category,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlCategory {
    Business,
    News,
    SocialMedia,
    Streaming,
    Gaming,
    Adult,
    Malware,
    Phishing,
    Gambling,
    Ads,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum UrlDecision {
    Allow,
    Block(BlockReason),
    Warn,
    Isolate, // Force pixel-push mode
}

#[derive(Debug, Clone, Copy)]
pub enum BlockReason {
    BlockedDomain,
    BlockedCategory,
    MalwareDetected,
    PhishingDetected,
    PolicyViolation,
}

impl UrlPolicy {
    pub fn new(mode: PolicyMode) -> Self {
        Self {
            allowed_domains: HashSet::new(),
            blocked_domains: HashSet::new(),
            blocked_patterns: Vec::new(),
            allowed_categories: HashSet::new(),
            mode,
        }
    }
    
    /// Check URL against policy
    pub fn check(&self, url: &str) -> UrlDecision {
        let domain = extract_domain(url);
        
        // Always block known malware/phishing
        if self.is_malware(&domain) {
            return UrlDecision::Block(BlockReason::MalwareDetected);
        }
        
        match self.mode {
            PolicyMode::Blacklist => {
                if self.blocked_domains.contains(&domain) {
                    UrlDecision::Block(BlockReason::BlockedDomain)
                } else if self.matches_pattern(url) {
                    UrlDecision::Block(BlockReason::PolicyViolation)
                } else {
                    UrlDecision::Allow
                }
            }
            PolicyMode::Whitelist => {
                if self.allowed_domains.contains(&domain) {
                    UrlDecision::Allow
                } else {
                    UrlDecision::Block(BlockReason::PolicyViolation)
                }
            }
            PolicyMode::Category => {
                let category = self.categorize(&domain);
                if self.allowed_categories.contains(&category) {
                    UrlDecision::Allow
                } else {
                    UrlDecision::Block(BlockReason::BlockedCategory)
                }
            }
        }
    }
    
    /// Add domain to blocklist
    pub fn block_domain(&mut self, domain: &str) {
        self.blocked_domains.insert(domain.to_lowercase());
    }
    
    /// Add domain to allowlist
    pub fn allow_domain(&mut self, domain: &str) {
        self.allowed_domains.insert(domain.to_lowercase());
    }
    
    fn is_malware(&self, _domain: &str) -> bool {
        // Would check against threat intelligence feed
        false
    }
    
    fn matches_pattern(&self, url: &str) -> bool {
        self.blocked_patterns.iter().any(|p| url.contains(p))
    }
    
    fn categorize(&self, _domain: &str) -> UrlCategory {
        // Would use URL categorization service
        UrlCategory::Unknown
    }
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self::new(PolicyMode::Blacklist)
    }
}

/// Data Loss Prevention policy
pub struct DlpPolicy {
    /// Patterns to detect (regex)
    patterns: Vec<DlpPattern>,
    /// Actions for violations
    actions: DlpActions,
}

#[derive(Debug, Clone)]
pub struct DlpPattern {
    pub name: String,
    pub pattern: String,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Copy)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct DlpActions {
    pub block_upload: bool,
    pub block_download: bool,
    pub block_clipboard: bool,
    pub log_violations: bool,
    pub alert_on_violation: bool,
}

impl Default for DlpActions {
    fn default() -> Self {
        Self {
            block_upload: true,
            block_download: false,
            block_clipboard: true,
            log_violations: true,
            alert_on_violation: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DlpViolation {
    pub pattern_name: String,
    pub content_preview: String,
    pub sensitivity: Sensitivity,
    pub action_taken: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl DlpPolicy {
    pub fn new() -> Self {
        Self {
            patterns: default_dlp_patterns(),
            actions: DlpActions::default(),
        }
    }
    
    /// Check content for DLP violations
    pub fn check(&self, content: &str) -> Vec<DlpViolation> {
        let mut violations = Vec::new();
        
        for pattern in &self.patterns {
            if let Ok(regex) = regex::Regex::new(&pattern.pattern) {
                if regex.is_match(content) {
                    violations.push(DlpViolation {
                        pattern_name: pattern.name.clone(),
                        content_preview: truncate(content, 50),
                        sensitivity: pattern.sensitivity,
                        action_taken: "blocked".to_string(),
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
        }
        
        violations
    }
    
    /// Check clipboard paste
    pub fn check_paste(&self, text: &str) -> Result<String, DlpViolation> {
        let violations = self.check(text);
        
        if violations.is_empty() || !self.actions.block_clipboard {
            Ok(text.to_string())
        } else {
            Err(violations.into_iter().next().unwrap())
        }
    }
}

impl Default for DlpPolicy {
    fn default() -> Self {
        Self::new()
    }
}

fn default_dlp_patterns() -> Vec<DlpPattern> {
    vec![
        DlpPattern {
            name: "Credit Card".to_string(),
            pattern: r"\b(?:\d{4}[- ]?){3}\d{4}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DlpPattern {
            name: "SSN".to_string(),
            pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DlpPattern {
            name: "Email".to_string(),
            pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
            sensitivity: Sensitivity::Medium,
        },
        DlpPattern {
            name: "AWS Key".to_string(),
            pattern: r"AKIA[0-9A-Z]{16}".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DlpPattern {
            name: "Private Key".to_string(),
            pattern: r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----".to_string(),
            sensitivity: Sensitivity::Critical,
        },
    ]
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

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_url_policy_blacklist() {
        let mut policy = UrlPolicy::new(PolicyMode::Blacklist);
        policy.block_domain("malware.com");
        
        assert!(matches!(policy.check("https://malware.com/test"), UrlDecision::Block(_)));
        assert!(matches!(policy.check("https://safe.com/test"), UrlDecision::Allow));
    }
    
    #[test]
    fn test_dlp_credit_card() {
        let policy = DlpPolicy::new();
        let violations = policy.check("My card is 4111-1111-1111-1111");
        
        assert!(!violations.is_empty());
        assert_eq!(violations[0].pattern_name, "Credit Card");
    }
}
