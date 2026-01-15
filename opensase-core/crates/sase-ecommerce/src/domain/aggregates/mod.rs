//! Aggregates module
pub mod product;
pub mod order;
pub mod cart;

pub use product::{Product, ProductError, ProductStatus};
pub use order::{Order, OrderError, OrderStatus, LineItem, Address};
pub use cart::{Cart, CartError, CartItem};
