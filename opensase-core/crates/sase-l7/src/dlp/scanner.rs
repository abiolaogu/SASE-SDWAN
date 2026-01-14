//! DLP Scanner - Content inspection engine

use crate::dlp::{DlpAction, DlpMatch, PatternType, Severity};
use crate::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn, debug};

/// DLP scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    /// Enable scanning
    pub enabled: bool,
    /// Default action
    pub default_action: DlpAction,
    /// Patterns to scan for
    pub patterns: Vec<PatternType>,
    /// Max content size to scan
    pub max_size: usize,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: DlpAction::Alert,
            patterns: vec![
                PatternType::SSN,
                PatternType::CreditCard,
                PatternType::ApiKey,
                PatternType::AwsKey,
            ],
            max_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// DLP Scanner
pub struct DlpScanner {
    config: DlpConfig,
    patterns: Vec<CompiledPattern>,
}

struct CompiledPattern {
    pattern_type: PatternType,
    regex: Regex,
    severity: Severity,
}

impl DlpScanner {
    /// Create new DLP scanner
    pub fn new(config: DlpConfig) -> Self {
        let patterns = config.patterns.iter()
            .filter_map(|pt| Self::compile_pattern(pt))
            .collect();
        
        Self { config, patterns }
    }
    
    /// Compile pattern to regex
    fn compile_pattern(pattern_type: &PatternType) -> Option<CompiledPattern> {
        let (regex_str, severity) = match pattern_type {
            PatternType::SSN => (
                r"\b\d{3}-\d{2}-\d{4}\b",
                Severity::High
            ),
            PatternType::CreditCard => (
                r"\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2}|3(?:0[0-5]|[68]\d)\d)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                Severity::Critical
            ),
            PatternType::ApiKey => (
                r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?[\w\-]{20,}",
                Severity::High
            ),
            PatternType::AwsKey => (
                r"(?i)(AKIA|ASIA)[A-Z0-9]{16}",
                Severity::Critical
            ),
            PatternType::PrivateKey => (
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
                Severity::Critical
            ),
            PatternType::Email => (
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                Severity::Low
            ),
            PatternType::PhoneNumber => (
                r"\b(?:\+?1[-.]?)?\(?[2-9]\d{2}\)?[-.]?\d{3}[-.]?\d{4}\b",
                Severity::Medium
            ),
            PatternType::Custom(pattern) => (
                pattern.as_str(),
                Severity::Medium
            ),
        };
        
        Regex::new(regex_str).ok().map(|regex| CompiledPattern {
            pattern_type: pattern_type.clone(),
            regex,
            severity,
        })
    }
    
    /// Scan content for sensitive data
    pub fn scan(&self, content: &str) -> Vec<DlpMatch> {
        if !self.config.enabled {
            return Vec::new();
        }
        
        if content.len() > self.config.max_size {
            warn!("Content too large for DLP scan: {} bytes", content.len());
            return Vec::new();
        }
        
        let mut matches = Vec::new();
        
        for pattern in &self.patterns {
            for mat in pattern.regex.find_iter(content) {
                let matched = mat.as_str();
                let redacted = Self::redact(matched, &pattern.pattern_type);
                
                debug!("DLP match: {:?} at {}", pattern.pattern_type, mat.start());
                
                matches.push(DlpMatch {
                    pattern_type: pattern.pattern_type.clone(),
                    offset: mat.start(),
                    length: matched.len(),
                    redacted,
                    severity: pattern.severity,
                });
            }
        }
        
        if !matches.is_empty() {
            info!("Found {} DLP matches", matches.len());
        }
        
        matches
    }
    
    /// Scan binary content
    pub fn scan_bytes(&self, content: &[u8]) -> Vec<DlpMatch> {
        // Try to convert to string
        if let Ok(text) = std::str::from_utf8(content) {
            self.scan(text)
        } else {
            // Scan lossy conversion
            let text = String::from_utf8_lossy(content);
            self.scan(&text)
        }
    }
    
    /// Redact matched content
    fn redact(content: &str, pattern_type: &PatternType) -> String {
        match pattern_type {
            PatternType::SSN => "***-**-****".to_string(),
            PatternType::CreditCard => {
                if content.len() >= 4 {
                    format!("****-****-****-{}", &content[content.len()-4..])
                } else {
                    "****-****-****-****".to_string()
                }
            }
            PatternType::Email => {
                if let Some(idx) = content.find('@') {
                    format!("***@{}", &content[idx+1..])
                } else {
                    "***@***.***".to_string()
                }
            }
            PatternType::PhoneNumber => "***-***-****".to_string(),
            _ => "*".repeat(content.len().min(20)),
        }
    }
    
    /// Redact content in place
    pub fn redact_content(&self, content: &str) -> String {
        let matches = self.scan(content);
        
        if matches.is_empty() {
            return content.to_string();
        }
        
        let mut result = content.to_string();
        let mut offset_adjustment = 0i64;
        
        for mat in matches {
            let start = (mat.offset as i64 + offset_adjustment) as usize;
            let end = start + mat.length;
            
            if end <= result.len() {
                let before = &result[..start];
                let after = &result[end..];
                let replacement = &mat.redacted;
                
                result = format!("{}{}{}", before, replacement, after);
                offset_adjustment += replacement.len() as i64 - mat.length as i64;
            }
        }
        
        result
    }
    
    /// Determine action based on matches
    pub fn determine_action(&self, matches: &[DlpMatch]) -> DlpAction {
        if matches.is_empty() {
            return DlpAction::Allow;
        }
        
        // If any critical match, block
        if matches.iter().any(|m| m.severity == Severity::Critical) {
            return DlpAction::Block;
        }
        
        // If any high severity, use configured default
        if matches.iter().any(|m| m.severity == Severity::High) {
            return self.config.default_action.clone();
        }
        
        // Otherwise alert
        DlpAction::Alert
    }
}

impl Default for DlpScanner {
    fn default() -> Self {
        Self::new(DlpConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ssn_detection() {
        let scanner = DlpScanner::default();
        let content = "My SSN is 123-45-6789 and I need help";
        let matches = scanner.scan(content);
        
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0].pattern_type, PatternType::SSN));
    }
    
    #[test]
    fn test_credit_card_detection() {
        let scanner = DlpScanner::default();
        let content = "Card: 4111-1111-1111-1111";
        let matches = scanner.scan(content);
        
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0].pattern_type, PatternType::CreditCard));
    }
    
    #[test]
    fn test_redaction() {
        let scanner = DlpScanner::default();
        let content = "SSN: 123-45-6789";
        let redacted = scanner.redact_content(content);
        
        assert!(redacted.contains("***-**-****"));
        assert!(!redacted.contains("123-45-6789"));
    }
}
