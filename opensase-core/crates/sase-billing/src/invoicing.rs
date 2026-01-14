//! Invoice Generation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use uuid::Uuid;
use chrono::{NaiveDate, Utc};

use crate::{BillingError, credits::Credit, subscriptions::Subscription, metering::MonthlyUsage};
use crate::pricing::{PricingEngine, LineItem};

/// Invoice generator
pub struct InvoiceGenerator {
    pricing: Arc<PricingEngine>,
    invoices: Arc<RwLock<HashMap<Uuid, Invoice>>>,
    sequence: Arc<RwLock<u64>>,
}

impl InvoiceGenerator {
    pub fn new(pricing: Arc<PricingEngine>) -> Self {
        Self {
            pricing,
            invoices: Arc::new(RwLock::new(HashMap::new())),
            sequence: Arc::new(RwLock::new(1000)),
        }
    }

    /// Generate invoice
    pub fn generate(
        &self,
        tenant_id: Uuid,
        subscription: &Subscription,
        usage: &MonthlyUsage,
        credits: &[Credit],
    ) -> Result<Invoice, BillingError> {
        let pricing = self.pricing.calculate(tenant_id, &subscription.plan_id, usage);
        if !pricing.success {
            return Err(BillingError::Invoice(pricing.error.unwrap_or_default()));
        }

        // Generate invoice number
        let invoice_number = {
            let mut seq = self.sequence.write();
            *seq += 1;
            format!("INV-{:06}", *seq)
        };

        // Build line items
        let mut items = vec![
            InvoiceLineItem {
                description: format!("{} Plan - Monthly", subscription.plan_id),
                quantity: 1.0,
                unit_price: pricing.base_price,
                amount: pricing.base_price,
                item_type: ItemType::Subscription,
            }
        ];

        // Add usage line items
        for line in &pricing.line_items {
            items.push(InvoiceLineItem {
                description: line.description.clone(),
                quantity: line.quantity,
                unit_price: line.unit_price,
                amount: line.amount,
                item_type: ItemType::Usage,
            });
        }

        // Apply credits
        let mut credits_applied = dec!(0);
        let mut credit_items = Vec::new();
        let mut remaining = pricing.total;

        for credit in credits.iter().filter(|c| c.is_active()) {
            if remaining <= dec!(0) {
                break;
            }
            let apply_amount = remaining.min(credit.remaining_amount);
            credits_applied += apply_amount;
            remaining -= apply_amount;

            credit_items.push(CreditApplication {
                credit_id: credit.id,
                description: format!("Credit: {}", credit.description),
                amount: apply_amount,
            });
        }

        // Calculate tax (placeholder - integrate with Avalara)
        let tax_rate = dec!(0.0875); // 8.75% example
        let taxable = remaining;
        let tax_amount = taxable * tax_rate;

        let total = remaining + tax_amount;

        let invoice = Invoice {
            id: Uuid::new_v4(),
            invoice_number,
            tenant_id,
            subscription_id: subscription.id,
            period_start: usage.month,
            period_end: usage.month + chrono::Duration::days(30),
            status: InvoiceStatus::Draft,
            line_items: items,
            subtotal: pricing.subtotal,
            discount: pricing.discount,
            credits_applied,
            credit_details: credit_items,
            tax_rate,
            tax_amount,
            total,
            currency: "USD".into(),
            due_date: Utc::now().naive_utc().date() + chrono::Duration::days(30),
            created_at: Utc::now(),
            paid_at: None,
        };

        self.invoices.write().insert(invoice.id, invoice.clone());
        Ok(invoice)
    }

    /// Get invoice
    pub fn get(&self, id: Uuid) -> Option<Invoice> {
        self.invoices.read().get(&id).cloned()
    }

    /// Get invoices for tenant
    pub fn get_for_tenant(&self, tenant_id: Uuid) -> Vec<Invoice> {
        self.invoices.read()
            .values()
            .filter(|i| i.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    /// Finalize invoice (lock for payment)
    pub fn finalize(&self, id: Uuid) -> Result<Invoice, BillingError> {
        let mut invoices = self.invoices.write();
        let invoice = invoices.get_mut(&id)
            .ok_or_else(|| BillingError::Invoice("Invoice not found".into()))?;
        
        if invoice.status != InvoiceStatus::Draft {
            return Err(BillingError::Invoice("Invoice already finalized".into()));
        }

        invoice.status = InvoiceStatus::Open;
        Ok(invoice.clone())
    }

    /// Mark invoice as paid
    pub fn mark_paid(&self, id: Uuid, payment_id: &str) -> Result<Invoice, BillingError> {
        let mut invoices = self.invoices.write();
        let invoice = invoices.get_mut(&id)
            .ok_or_else(|| BillingError::Invoice("Invoice not found".into()))?;
        
        invoice.status = InvoiceStatus::Paid;
        invoice.paid_at = Some(Utc::now());

        Ok(invoice.clone())
    }

    /// Export as JSON
    pub fn export_json(&self, id: Uuid) -> Option<String> {
        self.get(id).map(|i| serde_json::to_string_pretty(&i).unwrap_or_default())
    }
}

/// Invoice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: Uuid,
    pub invoice_number: String,
    pub tenant_id: Uuid,
    pub subscription_id: Uuid,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub status: InvoiceStatus,
    pub line_items: Vec<InvoiceLineItem>,
    pub subtotal: Decimal,
    pub discount: Decimal,
    pub credits_applied: Decimal,
    pub credit_details: Vec<CreditApplication>,
    pub tax_rate: Decimal,
    pub tax_amount: Decimal,
    pub total: Decimal,
    pub currency: String,
    pub due_date: NaiveDate,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub paid_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceStatus {
    Draft,
    Open,
    Paid,
    Void,
    Uncollectible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceLineItem {
    pub description: String,
    pub quantity: f64,
    pub unit_price: Decimal,
    pub amount: Decimal,
    pub item_type: ItemType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ItemType {
    Subscription,
    Usage,
    Credit,
    Adjustment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditApplication {
    pub credit_id: Uuid,
    pub description: String,
    pub amount: Decimal,
}
