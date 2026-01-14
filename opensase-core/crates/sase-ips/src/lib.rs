//! OpenSASE Inline Security Engine (OISE)
//!
//! High-performance IPS engine that integrates directly into VPP packet
//! processing using Hyperscan for pattern matching.
//!
//! ## Features
//!
//! - **Rule Compiler**: Parses Suricata/Snort rules and compiles to Hyperscan
//! - **Protocol Analyzers**: HTTP, TLS, DNS deep inspection
//! - **Alert Pipeline**: High-throughput alert aggregation with Wazuh integration
//! - **Hot Reload**: Update rules without traffic interruption
//!
//! ## Performance Targets
//!
//! - 40+ Gbps inspected throughput
//! - <100 μs additional latency
//! - 40,000+ compiled patterns
//! - 100K alerts/second

pub mod compiler;
pub mod parser;
pub mod protocols;
pub mod alerts;
pub mod engine;

pub use compiler::{RuleCompiler, CompiledDatabase, CompiledPattern};
pub use parser::{SuricataRule, RuleParser, RuleAction, Protocol};
pub use engine::{IpsEngine, InspectionResult, Verdict};

use thiserror::Error;

/// IPS Engine errors
#[derive(Error, Debug)]
pub enum IpsError {
    #[error("Rule parsing error: {0}")]
    ParseError(String),

    #[error("Compilation error: {0}")]
    CompileError(String),

    #[error("Hyperscan error: {0}")]
    HyperscanError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),

    #[error("Pattern too complex: {0}")]
    PatternTooComplex(String),
}

pub type Result<T> = std::result::Result<T, IpsError>;

/// Rule action types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionType {
    Alert,
    Drop,
    Reject,
    Pass,
    Log,
}

/// Rule severity levels
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Rule category
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Malware,
    Exploit,
    Botnet,
    Phishing,
    WebAttack,
    Dos,
    Scan,
    Policy,
    Protocol,
    Custom(String),
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malware => write!(f, "malware"),
            Self::Exploit => write!(f, "exploit"),
            Self::Botnet => write!(f, "botnet"),
            Self::Phishing => write!(f, "phishing"),
            Self::WebAttack => write!(f, "web-attack"),
            Self::Dos => write!(f, "dos"),
            Self::Scan => write!(f, "scan"),
            Self::Policy => write!(f, "policy"),
            Self::Protocol => write!(f, "protocol"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}
