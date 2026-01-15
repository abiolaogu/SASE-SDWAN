//! Order Aggregate

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;
use crate::domain::value_objects::Money;
use crate::domain::events::{DomainEvent, OrderEvent};

#[derive(Clone, Debug)]
pub struct Order {
    id: String,
    order_number: u64,
    customer_id: String,
    email: String,
    status: OrderStatus,
    fulfillment: FulfillmentStatus,
    payment: PaymentStatus,
    items: Vec<LineItem>,
    subtotal: Money,
    shipping: Money,
    tax: Money,
    discount: Money,
    total: Money,
    shipping_address: Option<Address>,
    billing_address: Option<Address>,
    notes: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    events: Vec<DomainEvent>,
}

#[derive(Clone, Debug)] pub struct LineItem { pub id: String, pub product_id: String, pub name: String, pub sku: String, pub quantity: u32, pub unit_price: Money, pub total: Money }
#[derive(Clone, Debug, Default)] pub struct Address { pub name: String, pub street1: String, pub street2: Option<String>, pub city: String, pub state: Option<String>, pub zip: String, pub country: String }
#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum OrderStatus { #[default] Pending, Confirmed, Processing, Shipped, Delivered, Cancelled, Refunded }
#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum FulfillmentStatus { #[default] Unfulfilled, Partial, Fulfilled }
#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum PaymentStatus { #[default] Pending, Authorized, Paid, Refunded, Voided }

impl Order {
    pub fn create(order_number: u64, customer_id: impl Into<String>, email: impl Into<String>, currency: &str) -> Self {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        Self {
            id: id.clone(), order_number, customer_id: customer_id.into(), email: email.into(),
            status: OrderStatus::Pending, fulfillment: FulfillmentStatus::Unfulfilled, payment: PaymentStatus::Pending,
            items: vec![], subtotal: Money::zero(currency), shipping: Money::zero(currency), tax: Money::zero(currency),
            discount: Money::zero(currency), total: Money::zero(currency), shipping_address: None, billing_address: None,
            notes: None, created_at: now, updated_at: now, events: vec![],
        }
    }
    
    pub fn id(&self) -> &str { &self.id }
    pub fn order_number(&self) -> u64 { self.order_number }
    pub fn status(&self) -> &OrderStatus { &self.status }
    pub fn total(&self) -> &Money { &self.total }
    pub fn items(&self) -> &[LineItem] { &self.items }
    
    pub fn add_item(&mut self, item: LineItem) { self.items.push(item); self.recalculate(); }
    
    pub fn confirm(&mut self) -> Result<(), OrderError> {
        if self.items.is_empty() { return Err(OrderError::NoItems); }
        self.status = OrderStatus::Confirmed;
        self.touch();
        self.raise_event(DomainEvent::Order(OrderEvent::Confirmed { order_id: self.id.clone(), total: self.total.amount() }));
        Ok(())
    }
    
    pub fn mark_paid(&mut self) { self.payment = PaymentStatus::Paid; self.status = OrderStatus::Processing; self.touch(); }
    pub fn ship(&mut self) { self.status = OrderStatus::Shipped; self.fulfillment = FulfillmentStatus::Fulfilled; self.touch(); }
    pub fn deliver(&mut self) { self.status = OrderStatus::Delivered; self.touch(); }
    
    pub fn cancel(&mut self) -> Result<(), OrderError> {
        if self.status == OrderStatus::Delivered { return Err(OrderError::CannotCancel); }
        self.status = OrderStatus::Cancelled;
        self.touch();
        self.raise_event(DomainEvent::Order(OrderEvent::Cancelled { order_id: self.id.clone() }));
        Ok(())
    }
    
    fn recalculate(&mut self) {
        self.subtotal = self.items.iter().fold(Money::zero(self.subtotal.currency()), |acc, i| acc.add(&i.total).unwrap_or(acc));
        self.total = self.subtotal.add(&self.shipping).unwrap_or(self.subtotal.clone());
        self.total = self.total.add(&self.tax).unwrap_or(self.total.clone());
        self.touch();
    }
    
    pub fn take_events(&mut self) -> Vec<DomainEvent> { std::mem::take(&mut self.events) }
    fn raise_event(&mut self, e: DomainEvent) { self.events.push(e); }
    fn touch(&mut self) { self.updated_at = Utc::now(); }
}

#[derive(Debug, Clone)] pub enum OrderError { NoItems, CannotCancel }
impl std::error::Error for OrderError {}
impl std::fmt::Display for OrderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::NoItems => write!(f, "No items"), Self::CannotCancel => write!(f, "Cannot cancel") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_order_workflow() {
        let mut order = Order::create(1001, "CUST001", "test@example.com", "USD");
        order.add_item(LineItem { id: "1".into(), product_id: "P1".into(), name: "Widget".into(), sku: "W001".into(), quantity: 2, unit_price: Money::usd(Decimal::new(10, 0)), total: Money::usd(Decimal::new(20, 0)) });
        order.confirm().unwrap();
        assert_eq!(order.status(), &OrderStatus::Confirmed);
        order.mark_paid();
        order.ship();
        assert_eq!(order.status(), &OrderStatus::Shipped);
    }
}
