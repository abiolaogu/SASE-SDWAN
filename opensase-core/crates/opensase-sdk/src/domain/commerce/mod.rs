//! Commerce domain types
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::common::{Address, Metadata};

/// Product
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Product {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub sku: String,
    pub price: i64,
    pub currency: String,
    pub status: String,
    #[serde(default)]
    pub images: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub inventory_quantity: Option<i32>,
    #[serde(default)]
    pub metadata: Metadata,
    pub created_at: DateTime<Utc>,
}

/// Order
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Order {
    pub id: String,
    pub order_number: String,
    pub customer_id: String,
    pub status: String,
    pub fulfillment_status: String,
    pub payment_status: String,
    #[serde(default)]
    pub line_items: Vec<LineItem>,
    pub subtotal: i64,
    pub shipping: i64,
    pub tax: i64,
    pub total: i64,
    pub currency: String,
    #[serde(default)]
    pub shipping_address: Option<Address>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LineItem {
    pub product_id: String,
    pub name: String,
    pub sku: String,
    pub quantity: u32,
    pub unit_price: i64,
    pub total: i64,
}

/// Cart
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Cart {
    pub id: String,
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub items: Vec<CartItem>,
    pub subtotal: i64,
    pub currency: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CartItem {
    pub product_id: String,
    pub name: String,
    pub quantity: u32,
    pub unit_price: i64,
}
