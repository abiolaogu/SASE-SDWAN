//! DLP Module - Data Loss Prevention
//!
//! Inline content inspection for sensitive data.

mod scanner;

pub use scanner::DlpScanner;

use serde::{Deserialize, Serialize};

/// DLP pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    SSN,
    CreditCard,
    ApiKey,
    AwsKey,
    PrivateKey,
    Email,
    PhoneNumber,
    Custom(String),
}

/// DLP match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpMatch {
    pub pattern_type: PatternType,
    pub offset: usize,
    pub length: usize,
    pub redacted: String,
    pub severity: Severity,
}

/// Severity level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// DLP action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DlpAction {
    Allow,
    Block,
    Redact,
    Alert,
}
