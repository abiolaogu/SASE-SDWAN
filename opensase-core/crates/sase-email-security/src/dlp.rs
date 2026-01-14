//! DLP Integration for Email
//!
//! Data Loss Prevention scanning for outbound emails.

use crate::{EmailMessage, DlpViolation, DlpSeverity, DlpMatch};
use std::collections::HashMap;

/// DLP engine for email content scanning
pub struct DlpEngine {
    /// DLP policies
    policies: Vec<DlpPolicy>,
}

#[derive(Debug, Clone)]
pub struct DlpPolicy {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub severity: DlpSeverity,
    pub patterns: Vec<DlpPattern>,
    pub conditions: Vec<DlpCondition>,
    pub action: DlpAction,
}

#[derive(Debug, Clone)]
pub struct DlpPattern {
    pub name: String,
    pub pattern_type: PatternType,
    pub pattern: String,
    pub validation: Option<ValidationRule>,
}

#[derive(Debug, Clone)]
pub enum PatternType {
    Regex,
    Keyword,
    Dictionary,
    Fingerprint,
}

#[derive(Debug, Clone)]
pub enum ValidationRule {
    LuhnCheck,      // Credit cards
    CheckDigit,     // SSN, etc.
    Checksum,       // Various IDs
}

#[derive(Debug, Clone)]
pub enum DlpCondition {
    MinMatches(u32),
    AttachmentPresent,
    RecipientExternal,
    SenderDepartment(String),
}

#[derive(Debug, Clone, Copy)]
pub enum DlpAction {
    Allow,
    Warn,
    Quarantine,
    Block,
    Encrypt,
    Redact,
}

#[derive(Debug, Clone)]
pub struct DlpResult {
    pub violations: Vec<DlpViolation>,
    pub action: DlpAction,
}

impl DlpEngine {
    pub fn new() -> Self {
        Self {
            policies: default_dlp_policies(),
        }
    }
    
    /// Scan email for DLP violations
    pub async fn scan(&self, message: &EmailMessage) -> DlpResult {
        let mut result = DlpResult {
            violations: Vec::new(),
            action: DlpAction::Allow,
        };
        
        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }
            
            let matches = self.check_policy(policy, message);
            
            if !matches.is_empty() {
                // Check conditions
                if self.conditions_met(&policy.conditions, message, &matches) {
                    result.violations.push(DlpViolation {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        severity: policy.severity,
                        matches,
                    });
                    
                    // Upgrade action if needed
                    result.action = more_restrictive(result.action, policy.action);
                }
            }
        }
        
        result
    }
    
    fn check_policy(&self, policy: &DlpPolicy, message: &EmailMessage) -> Vec<DlpMatch> {
        let mut matches = Vec::new();
        
        let body = message.body.text_plain.as_deref().unwrap_or("");
        let subject = &message.headers.subject;
        
        for pattern in &policy.patterns {
            // Check subject
            let subject_matches = self.find_matches(pattern, subject, "subject");
            matches.extend(subject_matches);
            
            // Check body
            let body_matches = self.find_matches(pattern, body, "body");
            matches.extend(body_matches);
            
            // Check attachments (filename only for now)
            for attachment in &message.attachments {
                let attachment_matches = self.find_matches(
                    pattern,
                    &attachment.filename,
                    &format!("attachment:{}", attachment.filename),
                );
                matches.extend(attachment_matches);
            }
        }
        
        matches
    }
    
    fn find_matches(&self, pattern: &DlpPattern, text: &str, location: &str) -> Vec<DlpMatch> {
        let mut matches = Vec::new();
        
        match pattern.pattern_type {
            PatternType::Regex => {
                if let Ok(re) = regex::Regex::new(&pattern.pattern) {
                    for mat in re.find_iter(text) {
                        let matched_text = mat.as_str().to_string();
                        
                        // Validate if needed
                        let valid = match &pattern.validation {
                            Some(ValidationRule::LuhnCheck) => luhn_check(&matched_text),
                            Some(ValidationRule::CheckDigit) => true, // Simplified
                            Some(ValidationRule::Checksum) => true,
                            None => true,
                        };
                        
                        if valid {
                            matches.push(DlpMatch {
                                pattern_name: pattern.name.clone(),
                                location: location.to_string(),
                                snippet: redact_match(&matched_text),
                            });
                        }
                    }
                }
            }
            PatternType::Keyword => {
                if text.to_lowercase().contains(&pattern.pattern.to_lowercase()) {
                    matches.push(DlpMatch {
                        pattern_name: pattern.name.clone(),
                        location: location.to_string(),
                        snippet: format!("...{}...", pattern.pattern),
                    });
                }
            }
            PatternType::Dictionary => {
                // Check against word list
            }
            PatternType::Fingerprint => {
                // Document fingerprinting
            }
        }
        
        matches
    }
    
    fn conditions_met(
        &self,
        conditions: &[DlpCondition],
        message: &EmailMessage,
        matches: &[DlpMatch],
    ) -> bool {
        for condition in conditions {
            match condition {
                DlpCondition::MinMatches(min) => {
                    if matches.len() < *min as usize {
                        return false;
                    }
                }
                DlpCondition::AttachmentPresent => {
                    if message.attachments.is_empty() {
                        return false;
                    }
                }
                DlpCondition::RecipientExternal => {
                    // Check if any recipient is external
                    // Would need org domain list
                }
                DlpCondition::SenderDepartment(_dept) => {
                    // Check sender's department
                }
            }
        }
        true
    }
    
    /// Add a DLP policy
    pub fn add_policy(&mut self, policy: DlpPolicy) {
        self.policies.push(policy);
    }
}

impl Default for DlpEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn more_restrictive(current: DlpAction, new: DlpAction) -> DlpAction {
    let severity = |a: DlpAction| match a {
        DlpAction::Allow => 0,
        DlpAction::Warn => 1,
        DlpAction::Encrypt => 2,
        DlpAction::Redact => 3,
        DlpAction::Quarantine => 4,
        DlpAction::Block => 5,
    };
    
    if severity(new) > severity(current) { new } else { current }
}

fn redact_match(text: &str) -> String {
    if text.len() <= 4 {
        "*".repeat(text.len())
    } else {
        let visible = &text[..2];
        let hidden = "*".repeat(text.len() - 4);
        let end = &text[text.len()-2..];
        format!("{}{}{}", visible, hidden, end)
    }
}

fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    
    let sum: u32 = digits.iter().rev().enumerate().map(|(i, &d)| {
        if i % 2 == 1 {
            let doubled = d * 2;
            if doubled > 9 { doubled - 9 } else { doubled }
        } else {
            d
        }
    }).sum();
    
    sum % 10 == 0
}

fn default_dlp_policies() -> Vec<DlpPolicy> {
    vec![
        // Credit Card Numbers
        DlpPolicy {
            id: "cc-numbers".to_string(),
            name: "Credit Card Numbers".to_string(),
            enabled: true,
            severity: DlpSeverity::High,
            patterns: vec![
                DlpPattern {
                    name: "Credit Card".to_string(),
                    pattern_type: PatternType::Regex,
                    pattern: r"\b(?:\d{4}[- ]?){3}\d{4}\b".to_string(),
                    validation: Some(ValidationRule::LuhnCheck),
                },
            ],
            conditions: vec![DlpCondition::MinMatches(1)],
            action: DlpAction::Quarantine,
        },
        
        // Social Security Numbers
        DlpPolicy {
            id: "ssn".to_string(),
            name: "Social Security Numbers".to_string(),
            enabled: true,
            severity: DlpSeverity::Critical,
            patterns: vec![
                DlpPattern {
                    name: "SSN".to_string(),
                    pattern_type: PatternType::Regex,
                    pattern: r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b".to_string(),
                    validation: None,
                },
            ],
            conditions: vec![DlpCondition::MinMatches(1)],
            action: DlpAction::Block,
        },
        
        // Confidential Keywords
        DlpPolicy {
            id: "confidential".to_string(),
            name: "Confidential Content".to_string(),
            enabled: true,
            severity: DlpSeverity::Medium,
            patterns: vec![
                DlpPattern {
                    name: "Confidential".to_string(),
                    pattern_type: PatternType::Keyword,
                    pattern: "strictly confidential".to_string(),
                    validation: None,
                },
                DlpPattern {
                    name: "Internal Only".to_string(),
                    pattern_type: PatternType::Keyword,
                    pattern: "internal use only".to_string(),
                    validation: None,
                },
            ],
            conditions: vec![],
            action: DlpAction::Warn,
        },
    ]
}
