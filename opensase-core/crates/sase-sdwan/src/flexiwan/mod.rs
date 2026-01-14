//! FlexiWAN Integration Module
//!
//! API client and synchronization for FlexiWAN SD-WAN controller.

mod client;
mod models;

pub use client::FlexiWanClient;
pub use models::*;
