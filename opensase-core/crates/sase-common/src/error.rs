//! Error types for OpenSASE

use thiserror::Error;

/// OpenSASE error type
#[derive(Error, Debug)]
pub enum SaseError {
    /// Policy not found
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    /// Invalid policy
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    /// Flow table full
    #[error("flow table full")]
    FlowTableFull,

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// DLP violation
    #[error("DLP violation: {classifier}")]
    DLPViolation { classifier: String },

    /// Authentication failed
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// XDP error
    #[error("XDP error: {0}")]
    XdpError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Configuration error
    #[error("config error: {0}")]
    ConfigError(String),
}

/// Result type for OpenSASE
pub type SaseResult<T> = Result<T, SaseError>;
