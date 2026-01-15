//! Cart Aggregate

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;
use crate::domain::value_objects::Money;

#[derive(Clone, Debug)]
pub struct Cart {
    id: String,
    customer_id: Option<String>,
    session_id: Option<String>,
    items: Vec<CartItem>,
    subtotal: Money,
    currency: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct CartItem {
    pub product_id: String,
    pub variant_id: Option<String>,
    pub name: String,
    pub sku: String,
    pub quantity: u32,
    pub unit_price: Money,
}

impl CartItem {
    pub fn line_total(&self) -> Money { self.unit_price.multiply(self.quantity) }
}

impl Cart {
    pub fn new(currency: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(), customer_id: None, session_id: None,
            items: vec![], subtotal: Money::zero(currency), currency: currency.to_string(),
            created_at: Utc::now(), updated_at: Utc::now(),
        }
    }
    
    pub fn for_customer(customer_id: impl Into<String>, currency: &str) -> Self {
        let mut cart = Self::new(currency);
        cart.customer_id = Some(customer_id.into());
        cart
    }
    
    pub fn id(&self) -> &str { &self.id }
    pub fn items(&self) -> &[CartItem] { &self.items }
    pub fn subtotal(&self) -> &Money { &self.subtotal }
    pub fn item_count(&self) -> usize { self.items.len() }
    pub fn is_empty(&self) -> bool { self.items.is_empty() }
    
    pub fn add_item(&mut self, item: CartItem) {
        if let Some(existing) = self.items.iter_mut().find(|i| i.product_id == item.product_id && i.variant_id == item.variant_id) {
            existing.quantity += item.quantity;
        } else {
            self.items.push(item);
        }
        self.recalculate();
    }
    
    pub fn update_quantity(&mut self, product_id: &str, quantity: u32) -> Result<(), CartError> {
        let item = self.items.iter_mut().find(|i| i.product_id == product_id).ok_or(CartError::ItemNotFound)?;
        if quantity == 0 { self.items.retain(|i| i.product_id != product_id); }
        else { item.quantity = quantity; }
        self.recalculate();
        Ok(())
    }
    
    pub fn remove_item(&mut self, product_id: &str) -> Result<(), CartError> {
        let before = self.items.len();
        self.items.retain(|i| i.product_id != product_id);
        if self.items.len() == before { return Err(CartError::ItemNotFound); }
        self.recalculate();
        Ok(())
    }
    
    pub fn clear(&mut self) { self.items.clear(); self.recalculate(); }
    
    fn recalculate(&mut self) {
        self.subtotal = self.items.iter().fold(Money::zero(&self.currency), |acc, i| acc.add(&i.line_total()).unwrap_or(acc));
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone)] pub enum CartError { ItemNotFound }
impl std::error::Error for CartError {}
impl std::fmt::Display for CartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Item not found") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cart_operations() {
        let mut cart = Cart::new("USD");
        cart.add_item(CartItem { product_id: "P1".into(), variant_id: None, name: "Widget".into(), sku: "W1".into(), quantity: 2, unit_price: Money::usd(Decimal::new(10, 0)) });
        assert_eq!(cart.item_count(), 1);
        assert_eq!(cart.subtotal().amount(), Decimal::new(20, 0));
        cart.add_item(CartItem { product_id: "P1".into(), variant_id: None, name: "Widget".into(), sku: "W1".into(), quantity: 1, unit_price: Money::usd(Decimal::new(10, 0)) });
        assert_eq!(cart.items()[0].quantity, 3); // Merged
    }
}
