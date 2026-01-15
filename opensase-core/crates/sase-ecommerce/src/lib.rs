//! OpenSASE E-commerce Platform - DDD Implementation
//!
//! Self-hosted e-commerce replacing Shopify, WooCommerce.

pub mod domain;

pub use domain::aggregates::{Product, Order, Cart, ProductError, OrderError, CartError};
pub use domain::value_objects::{Sku, Money, Quantity};
pub use domain::events::{DomainEvent, ProductEvent, OrderEvent};
