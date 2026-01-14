//! Ultra-Fast DLP Scanner
//!
//! Target: 10GB/s throughput, <50μs per 1KB scan
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    DLP Scan Pipeline                        │
//! │                                                             │
//! │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐       │
//! │  │Aho-Corasick │   │   Entropy   │   │   Luhn/     │       │
//! │  │Multi-Pattern│   │    SIMD     │   │  Checksum   │       │
//! │  │   O(n)      │   │   AVX2      │   │  Validate   │       │
//! │  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘       │
//! │         │                  │                  │             │
//! │         └─────────────────┬┴─────────────────┘             │
//! │                           │                                 │
//! │                    ┌──────▼──────┐                         │
//! │                    │   Matches   │                         │
//! │                    │  Aggregator │                         │
//! │                    └─────────────┘                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]

pub mod scanner;
pub mod patterns;
pub mod entropy;
pub mod checksum;

pub use scanner::{DLPScanner, ScanResult, Match};
pub use patterns::PatternSet;

use serde::{Deserialize, Serialize};

/// DLP severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    /// Informational
    Info = 0,
    /// Low risk
    Low = 1,
    /// Medium risk
    Medium = 2,
    /// High risk
    High = 3,
    /// Critical risk
    Critical = 4,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Medium
    }
}

/// Classifier type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassifierType {
    /// Simple substring match
    Literal,
    /// Regular expression
    Regex,
    /// Entropy-based detection
    Entropy,
    /// Checksum validation (Luhn, etc.)
    Checksum,
}

/// Classifier definition
#[derive(Debug, Clone)]
pub struct Classifier {
    /// Unique identifier
    pub id: u32,
    /// Human-readable name
    pub name: String,
    /// Pattern to match
    pub pattern: String,
    /// Classifier type
    pub classifier_type: ClassifierType,
    /// Severity level
    pub severity: Severity,
    /// Whether to validate with checksum
    pub validate_checksum: bool,
}

impl Classifier {
    /// Create SSN classifier
    pub fn ssn() -> Self {
        Self {
            id: 1,
            name: "ssn".to_string(),
            pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
            classifier_type: ClassifierType::Regex,
            severity: Severity::High,
            validate_checksum: true,
        }
    }

    /// Create credit card classifier
    pub fn credit_card() -> Self {
        Self {
            id: 2,
            name: "credit_card".to_string(),
            pattern: r"\b(?:\d{4}[-\s]?){3}\d{4}\b".to_string(),
            classifier_type: ClassifierType::Regex,
            severity: Severity::High,
            validate_checksum: true,  // Luhn
        }
    }

    /// Create AWS access key classifier
    pub fn aws_access_key() -> Self {
        Self {
            id: 3,
            name: "aws_access_key".to_string(),
            pattern: r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b".to_string(),
            classifier_type: ClassifierType::Regex,
            severity: Severity::Critical,
            validate_checksum: false,
        }
    }

    /// Create private key classifier
    pub fn private_key() -> Self {
        Self {
            id: 4,
            name: "private_key".to_string(),
            pattern: "-----BEGIN".to_string(),  // Fast literal match
            classifier_type: ClassifierType::Literal,
            severity: Severity::Critical,
            validate_checksum: false,
        }
    }

    /// Create high-entropy classifier
    pub fn high_entropy() -> Self {
        Self {
            id: 5,
            name: "high_entropy".to_string(),
            pattern: String::new(),  // No pattern, entropy-based
            classifier_type: ClassifierType::Entropy,
            severity: Severity::High,
            validate_checksum: false,
        }
    }
}

/// Get default classifier set
pub fn default_classifiers() -> Vec<Classifier> {
    vec![
        Classifier::ssn(),
        Classifier::credit_card(),
        Classifier::aws_access_key(),
        Classifier::private_key(),
        Classifier::high_entropy(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classifier_defaults() {
        let classifiers = default_classifiers();
        assert_eq!(classifiers.len(), 5);
        assert_eq!(classifiers[0].name, "ssn");
        assert_eq!(classifiers[1].name, "credit_card");
    }
}
