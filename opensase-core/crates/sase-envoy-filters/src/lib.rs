//! OpenSASE Envoy WASM Filters
//!
//! High-performance security filters for Envoy Proxy.
//!
//! ## Filters
//!
//! - **URL Filter**: URL categorization and blocking
//! - **DLP Filter**: Data Loss Prevention
//! - **CASB Filter**: Cloud App Security Broker
//!
//! ## Build
//!
//! ```bash
//! cargo build --target wasm32-wasi --release
//! ```

mod url_filter;
mod dlp_filter;
mod casb_filter;

// Re-export for WASM runtime
pub use url_filter::UrlFilter;
pub use dlp_filter::DlpFilter;
pub use casb_filter::CasbFilter;
