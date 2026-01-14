//! OpenSASE Envoy WASM Filters
//!
//! High-performance security filters for Envoy Proxy.
//!
//! ## Filters
//!
//! - **AuthZ Filter**: Policy-based authorization
//! - **URL Filter**: URL categorization and blocking
//! - **DLP Filter**: Data Loss Prevention
//! - **CASB Filter**: Cloud App Security Broker
//! - **Malware Filter**: File scanning and hash checking
//!
//! ## Build
//!
//! ```bash
//! cargo build --target wasm32-wasi --release
//! ```

mod authz_filter;
mod url_filter;
mod dlp_filter;
mod casb_filter;
mod malware_filter;

// Re-export for WASM runtime
pub use authz_filter::AuthzFilter;
pub use url_filter::UrlFilter;
pub use dlp_filter::DlpFilter;
pub use casb_filter::CasbFilter;
pub use malware_filter::MalwareScanner;
