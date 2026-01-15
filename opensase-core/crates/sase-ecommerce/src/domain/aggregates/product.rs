//! Product Aggregate

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;
use crate::domain::value_objects::{Sku, Money, Quantity};
use crate::domain::events::{DomainEvent, ProductEvent};

#[derive(Clone, Debug)]
pub struct Product {
    id: String,
    sku: Sku,
    name: String,
    description: String,
    price: Money,
    compare_at_price: Option<Money>,
    cost: Option<Money>,
    inventory: Quantity,
    status: ProductStatus,
    categories: Vec<String>,
    tags: Vec<String>,
    variants: Vec<Variant>,
    images: Vec<ProductImage>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    events: Vec<DomainEvent>,
}

#[derive(Clone, Debug)] pub struct Variant { pub id: String, pub sku: Option<Sku>, pub name: String, pub price: Money, pub inventory: Quantity }
#[derive(Clone, Debug)] pub struct ProductImage { pub url: String, pub alt: Option<String>, pub position: u32 }
#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum ProductStatus { #[default] Draft, Active, Archived }

impl Product {
    pub fn create(sku: Sku, name: impl Into<String>, price: Money) -> Self {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let mut product = Self {
            id: id.clone(), sku: sku.clone(), name: name.into(), description: String::new(),
            price, compare_at_price: None, cost: None, inventory: Quantity::default(),
            status: ProductStatus::Draft, categories: vec![], tags: vec![], variants: vec![],
            images: vec![], created_at: now, updated_at: now, events: vec![],
        };
        product.raise_event(DomainEvent::Product(ProductEvent::Created { product_id: id, sku }));
        product
    }
    
    pub fn id(&self) -> &str { &self.id }
    pub fn sku(&self) -> &Sku { &self.sku }
    pub fn name(&self) -> &str { &self.name }
    pub fn price(&self) -> &Money { &self.price }
    pub fn inventory(&self) -> &Quantity { &self.inventory }
    pub fn status(&self) -> &ProductStatus { &self.status }
    pub fn is_in_stock(&self) -> bool { !self.inventory.is_zero() }
    
    pub fn publish(&mut self) -> Result<(), ProductError> {
        if self.name.is_empty() { return Err(ProductError::MissingName); }
        self.status = ProductStatus::Active;
        self.touch();
        Ok(())
    }
    
    pub fn archive(&mut self) { self.status = ProductStatus::Archived; self.touch(); }
    
    pub fn update_price(&mut self, new_price: Money) {
        self.price = new_price;
        self.touch();
    }
    
    pub fn add_inventory(&mut self, qty: u32) {
        self.inventory = self.inventory.add(qty);
        self.touch();
        self.raise_event(DomainEvent::Product(ProductEvent::InventoryAdded { product_id: self.id.clone(), quantity: qty }));
    }
    
    pub fn remove_inventory(&mut self, qty: u32) -> Result<(), ProductError> {
        self.inventory = self.inventory.subtract(qty).ok_or(ProductError::InsufficientInventory)?;
        self.touch();
        Ok(())
    }
    
    pub fn take_events(&mut self) -> Vec<DomainEvent> { std::mem::take(&mut self.events) }
    fn raise_event(&mut self, e: DomainEvent) { self.events.push(e); }
    fn touch(&mut self) { self.updated_at = Utc::now(); }
}

#[derive(Debug, Clone)] pub enum ProductError { MissingName, InsufficientInventory }
impl std::error::Error for ProductError {}
impl std::fmt::Display for ProductError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::MissingName => write!(f, "Missing name"), Self::InsufficientInventory => write!(f, "Insufficient inventory") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_product_create() {
        let p = Product::create(Sku::new("TEST-001").unwrap(), "Test Product", Money::usd(Decimal::new(1999, 2)));
        assert_eq!(p.name(), "Test Product");
    }
    #[test]
    fn test_inventory() {
        let mut p = Product::create(Sku::new("TEST").unwrap(), "P", Money::usd(Decimal::new(10, 0)));
        p.add_inventory(10);
        assert!(p.is_in_stock());
        p.remove_inventory(5).unwrap();
        assert_eq!(p.inventory().value(), 5);
    }
}
