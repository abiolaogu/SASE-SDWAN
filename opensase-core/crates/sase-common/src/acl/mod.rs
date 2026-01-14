//! Anti-Corruption Layer (ACL)
//!
//! # Legacy Modernization Pattern
//!
//! The ACL protects the clean domain model from external systems:
//! - Translates between domain and external models
//! - Validates external data before entering domain
//! - Provides facade for legacy Python components
//!
//! ## Strangler Fig Strategy
//! - New Rust services call legacy Python via ACL
//! - Gradually replace Python components
//! - ACL shrinks as modernization progresses

pub mod python_adapter;
pub mod flexiwan_adapter;
pub mod opnsense_adapter;
pub mod wazuh_adapter;

pub use python_adapter::*;
