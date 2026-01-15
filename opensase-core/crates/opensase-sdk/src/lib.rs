//! OpenSASE Rust SDK
//!
//! A comprehensive, async-first Rust SDK for the OpenSASE Platform API.
//! 
//! # Architecture
//! 
//! This SDK follows DDD principles with:
//! - **Domain Layer**: Value objects for API entities (User, Contact, Payment)
//! - **Application Layer**: Service clients that orchestrate API calls
//! - **Infrastructure Layer**: HTTP client with retry, rate-limiting
//!
//! # Example
//!
//! ```rust,no_run
//! use opensase_sdk::{Client, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let client = Client::new("os_live_abc123...");
//!
//!     // Create a contact
//!     let contact = client.crm().contacts().create(
//!         CreateContactParams::builder()
//!             .email("john@example.com")
//!             .build()
//!     ).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod domain;
pub mod services;
pub mod client;
pub mod error;
pub mod webhooks;

pub use client::Client;
pub use error::{Error, Result};
pub use domain::*;

/// SDK version
pub const VERSION: &str = "1.0.0";

/// Default API base URL
pub const DEFAULT_BASE_URL: &str = "https://api.opensase.billyronks.io/v1";
