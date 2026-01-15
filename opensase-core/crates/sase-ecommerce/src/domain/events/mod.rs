//! Domain events
use crate::domain::value_objects::Sku;
use rust_decimal::Decimal;

#[derive(Clone, Debug)]
pub enum DomainEvent {
    Product(ProductEvent),
    Order(OrderEvent),
}

#[derive(Clone, Debug)]
pub enum ProductEvent {
    Created { product_id: String, sku: Sku },
    Published { product_id: String },
    InventoryAdded { product_id: String, quantity: u32 },
    InventoryRemoved { product_id: String, quantity: u32 },
}

#[derive(Clone, Debug)]
pub enum OrderEvent {
    Created { order_id: String, customer_id: String },
    Confirmed { order_id: String, total: Decimal },
    Paid { order_id: String },
    Shipped { order_id: String, tracking: Option<String> },
    Delivered { order_id: String },
    Cancelled { order_id: String },
}
