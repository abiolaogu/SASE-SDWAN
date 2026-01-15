//! OpenSASE E-commerce Platform
//!
//! Self-hosted e-commerce replacing Shopify, WooCommerce, Magento.
//!
//! ## Features
//! - Product catalog management
//! - Shopping cart and checkout
//! - Order management
//! - Inventory tracking
//! - Multi-currency support

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// Core Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Product {
    pub id: String,
    pub sku: String,
    pub name: String,
    pub description: String,
    pub price: Money,
    pub compare_at_price: Option<Money>,
    pub cost: Option<Money>,
    pub category_id: Option<String>,
    pub vendor: Option<String>,
    pub product_type: Option<String>,
    pub tags: Vec<String>,
    pub variants: Vec<ProductVariant>,
    pub images: Vec<ProductImage>,
    pub status: ProductStatus,
    pub inventory_policy: InventoryPolicy,
    pub seo: SeoData,
    pub custom_fields: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Money {
    pub amount: Decimal,
    pub currency: String,
}

impl Default for Money {
    fn default() -> Self {
        Self {
            amount: Decimal::ZERO,
            currency: "USD".to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum ProductStatus {
    #[default]
    Draft,
    Active,
    Archived,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum InventoryPolicy {
    #[default]
    Deny,
    Continue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProductVariant {
    pub id: String,
    pub sku: Option<String>,
    pub title: String,
    pub price: Money,
    pub compare_at_price: Option<Money>,
    pub inventory_quantity: i32,
    pub weight: Option<f64>,
    pub weight_unit: WeightUnit,
    pub options: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum WeightUnit {
    #[default]
    Kg,
    Lb,
    Oz,
    G,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProductImage {
    pub id: String,
    pub url: String,
    pub alt_text: Option<String>,
    pub position: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SeoData {
    pub title: Option<String>,
    pub description: Option<String>,
    pub handle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub order_number: u64,
    pub customer_id: String,
    pub email: String,
    pub status: OrderStatus,
    pub fulfillment_status: FulfillmentStatus,
    pub payment_status: PaymentStatus,
    pub line_items: Vec<LineItem>,
    pub subtotal: Money,
    pub shipping_total: Money,
    pub tax_total: Money,
    pub discount_total: Money,
    pub total: Money,
    pub shipping_address: Option<Address>,
    pub billing_address: Option<Address>,
    pub note: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum OrderStatus {
    #[default]
    Pending,
    Confirmed,
    Processing,
    Shipped,
    Delivered,
    Cancelled,
    Refunded,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum FulfillmentStatus {
    #[default]
    Unfulfilled,
    PartiallyFulfilled,
    Fulfilled,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum PaymentStatus {
    #[default]
    Pending,
    Authorized,
    Paid,
    PartiallyRefunded,
    Refunded,
    Voided,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LineItem {
    pub id: String,
    pub product_id: String,
    pub variant_id: Option<String>,
    pub title: String,
    pub quantity: u32,
    pub price: Money,
    pub total: Money,
    pub sku: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Address {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub address1: String,
    pub address2: Option<String>,
    pub city: String,
    pub province: Option<String>,
    pub country: String,
    pub zip: String,
    pub phone: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cart {
    pub id: String,
    pub customer_id: Option<String>,
    pub items: Vec<CartItem>,
    pub subtotal: Money,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CartItem {
    pub product_id: String,
    pub variant_id: Option<String>,
    pub quantity: u32,
    pub price: Money,
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum EcommerceError {
    #[error("Product not found")]
    ProductNotFound,
    
    #[error("Order not found")]
    OrderNotFound,
    
    #[error("Cart not found")]
    CartNotFound,
    
    #[error("Insufficient inventory")]
    InsufficientInventory,
    
    #[error("Invalid quantity")]
    InvalidQuantity,
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type Result<T> = std::result::Result<T, EcommerceError>;
