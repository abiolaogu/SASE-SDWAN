//! Service layer
use crate::client::Client;
use crate::domain::*;
use crate::error::Result;

pub struct IdentityService { client: Client }
impl IdentityService {
    pub fn new(client: Client) -> Self { Self { client } }
    pub fn users(&self) -> UsersApi { UsersApi { client: self.client.clone() } }
}

pub struct UsersApi { client: Client }
impl UsersApi {
    pub async fn create(&self, params: CreateUserParams) -> Result<User> { self.client.post("/identity/users", params).await }
    pub async fn get(&self, id: &str) -> Result<User> { self.client.get(&format!("/identity/users/{}", id)).await }
    pub async fn list(&self) -> Result<ListResponse<User>> { self.client.get("/identity/users").await }
    pub async fn delete(&self, id: &str) -> Result<()> { self.client.delete(&format!("/identity/users/{}", id)).await }
}

pub struct CrmService { client: Client }
impl CrmService {
    pub fn new(client: Client) -> Self { Self { client } }
    pub fn contacts(&self) -> ContactsApi { ContactsApi { client: self.client.clone() } }
}

pub struct ContactsApi { client: Client }
impl ContactsApi {
    pub async fn create(&self, params: CreateContactParams) -> Result<Contact> { self.client.post("/crm/contacts", params).await }
    pub async fn get(&self, id: &str) -> Result<Contact> { self.client.get(&format!("/crm/contacts/{}", id)).await }
    pub async fn list(&self) -> Result<ListResponse<Contact>> { self.client.get("/crm/contacts").await }
    pub async fn delete(&self, id: &str) -> Result<()> { self.client.delete(&format!("/crm/contacts/{}", id)).await }
}

pub struct PaymentsService { client: Client }
impl PaymentsService {
    pub fn new(client: Client) -> Self { Self { client } }
    pub fn payment_intents(&self) -> PaymentIntentsApi { PaymentIntentsApi { client: self.client.clone() } }
    pub fn subscriptions(&self) -> SubscriptionsApi { SubscriptionsApi { client: self.client.clone() } }
}

pub struct PaymentIntentsApi { client: Client }
impl PaymentIntentsApi {
    pub async fn create(&self, params: CreatePaymentIntentParams) -> Result<PaymentIntent> { self.client.post("/payments/intents", params).await }
    pub async fn get(&self, id: &str) -> Result<PaymentIntent> { self.client.get(&format!("/payments/intents/{}", id)).await }
    pub async fn confirm(&self, id: &str) -> Result<PaymentIntent> { self.client.post(&format!("/payments/intents/{}/confirm", id), ()).await }
    pub async fn cancel(&self, id: &str) -> Result<PaymentIntent> { self.client.post(&format!("/payments/intents/{}/cancel", id), ()).await }
}

pub struct SubscriptionsApi { client: Client }
impl SubscriptionsApi {
    pub async fn get(&self, id: &str) -> Result<Subscription> { self.client.get(&format!("/payments/subscriptions/{}", id)).await }
    pub async fn list(&self) -> Result<ListResponse<Subscription>> { self.client.get("/payments/subscriptions").await }
    pub async fn cancel(&self, id: &str) -> Result<Subscription> { self.client.post(&format!("/payments/subscriptions/{}/cancel", id), ()).await }
}
