//! Error types
use thiserror::Error;
use serde::{Deserialize, Serialize};

/// OpenSASE SDK Error
#[derive(Error, Debug)]
pub enum Error {
    #[error("API error: {code} - {message}")]
    Api {
        code: String,
        message: String,
        status_code: u16,
        request_id: Option<String>,
        details: Vec<ErrorDetail>,
    },
    #[error("Rate limit exceeded. Retry after {retry_after} seconds")]
    RateLimit { retry_after: u64, limit: u64, remaining: u64 },
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid configuration: {0}")]
    Config(String),
    #[error("Invalid webhook signature")]
    InvalidSignature,
}

impl Error {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::RateLimit { .. } | Error::Api { status_code: 500..=599, .. })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorDetail { pub field: String, pub code: String, pub message: String }

/// Result alias
pub type Result<T> = std::result::Result<T, Error>;
