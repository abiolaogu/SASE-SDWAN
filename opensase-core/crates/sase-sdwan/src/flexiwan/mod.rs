//! FlexiWAN Integration Module
//!
//! API client and synchronization for FlexiWAN SD-WAN controller.

mod client;
mod models;
mod api;

pub use client::FlexiWanClient;
pub use models::*;
pub use api::FlexiWanApi;
