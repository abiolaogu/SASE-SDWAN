//! OpenSASE xDS Control Plane
//!
//! gRPC-based xDS server for dynamic Envoy configuration.
//!
//! ## Services
//!
//! - **LDS**: Listener Discovery Service
//! - **CDS**: Cluster Discovery Service
//! - **RDS**: Route Discovery Service
//! - **EDS**: Endpoint Discovery Service
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sase_xds::XdsServer;
//!
//! let server = XdsServer::new();
//! server.serve("[::]:18000").await?;
//! ```

pub mod server;
pub mod discovery;
pub mod resources;

pub use server::XdsServer;
pub use discovery::{LdsService, CdsService, RdsService};
pub use resources::{Listener, Cluster, RouteConfiguration};

use thiserror::Error;

/// xDS errors
#[derive(Error, Debug)]
pub enum XdsError {
    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Invalid resource: {0}")]
    InvalidResource(String),

    #[error("gRPC error: {0}")]
    GrpcError(#[from] tonic::Status),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, XdsError>;
