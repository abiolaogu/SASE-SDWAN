//! OpenSASE Layer 7 Gateway Services
//!
//! High-performance L7 security services for SASE.
//!
//! ## Components
//!
//! - **AuthZ**: gRPC Policy Engine for authorization
//! - **SWG**: URL filtering and categorization
//! - **CASB**: SaaS application connectors
//! - **DLP**: Data Loss Prevention inspection
//!
//! ## Performance Targets
//!
//! - 20 Gbps HTTPS throughput
//! - <10ms AuthZ latency (p99)
//! - 100K URL lookups/sec

pub mod authz;
pub mod swg;
pub mod casb;
pub mod dlp;

pub use authz::PolicyEngine;
pub use swg::UrlFilterService;
pub use casb::CasbService;

use thiserror::Error;

/// L7 Gateway errors
#[derive(Error, Debug)]
pub enum L7Error {
    #[error("Policy evaluation failed: {0}")]
    PolicyError(String),

    #[error("URL filter error: {0}")]
    UrlFilterError(String),

    #[error("CASB connector error: {0}")]
    CasbError(String),

    #[error("DLP scan error: {0}")]
    DlpError(String),

    #[error("gRPC error: {0}")]
    GrpcError(#[from] tonic::Status),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, L7Error>;
