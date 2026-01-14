//! SWG Module - Secure Web Gateway
//!
//! URL filtering and categorization service.

mod filter;
mod category;
mod blocklist;

pub use filter::UrlFilterService;
pub use category::{Category, CategoryDatabase};
pub use blocklist::BlocklistManager;
