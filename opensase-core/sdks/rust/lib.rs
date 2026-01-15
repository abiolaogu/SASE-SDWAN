//! OpenSASE Rust SDK
//!
//! A comprehensive, async-first Rust SDK for the OpenSASE Platform API.
//!
//! # Example
//!
//! ```rust,no_run
//! use opensase::{Client, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let client = Client::new("os_live_abc123...");
//!
//!     // Create a user
//!     let user = client.identity().users().create(
//!         CreateUserParams::builder()
//!             .email("john@example.com")
//!             .build()
//!     ).await?;
//!
//!     // List contacts
//!     let contacts = client.crm().contacts().list(
//!         ListContactsParams::default()
//!     ).await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{header, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use url::Url;

pub use error::*;
pub use types::*;

pub mod error;
pub mod types;
pub mod services;
pub mod webhooks;

/// SDK version
pub const VERSION: &str = "1.0.0";

/// Default API base URL
pub const DEFAULT_BASE_URL: &str = "https://api.opensase.billyronks.io/v1";

/// Default request timeout
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default max retries
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Result type alias for OpenSASE operations
pub type Result<T> = std::result::Result<T, Error>;

// =============================================================================
// Error Types
// =============================================================================

pub mod error {
    use super::*;

    /// Error type for OpenSASE SDK operations
    #[derive(Error, Debug)]
    pub enum Error {
        /// API error returned by the server
        #[error("API error: {code} - {message}")]
        Api {
            code: String,
            message: String,
            status_code: u16,
            request_id: Option<String>,
            details: Vec<ErrorDetail>,
        },

        /// Rate limit exceeded
        #[error("Rate limit exceeded. Retry after {retry_after} seconds")]
        RateLimit {
            retry_after: u64,
            limit: u64,
            remaining: u64,
            request_id: Option<String>,
        },

        /// HTTP client error
        #[error("HTTP error: {0}")]
        Http(#[from] reqwest::Error),

        /// JSON serialization/deserialization error
        #[error("JSON error: {0}")]
        Json(#[from] serde_json::Error),

        /// URL parsing error
        #[error("URL error: {0}")]
        Url(#[from] url::ParseError),

        /// Invalid configuration
        #[error("Configuration error: {0}")]
        Config(String),

        /// Webhook signature verification failed
        #[error("Invalid webhook signature")]
        InvalidSignature,

        /// Webhook timestamp outside tolerance
        #[error("Webhook timestamp outside tolerance")]
        TimestampOutsideTolerance,
    }

    impl Error {
        /// Returns true if this is a validation error (400)
        pub fn is_validation_error(&self) -> bool {
            matches!(self, Error::Api { status_code: 400, .. })
        }

        /// Returns true if this is an authentication error (401)
        pub fn is_authentication_error(&self) -> bool {
            matches!(self, Error::Api { status_code: 401, .. })
        }

        /// Returns true if this is an authorization error (403)
        pub fn is_authorization_error(&self) -> bool {
            matches!(self, Error::Api { status_code: 403, .. })
        }

        /// Returns true if this is a not found error (404)
        pub fn is_not_found_error(&self) -> bool {
            matches!(self, Error::Api { status_code: 404, .. })
        }

        /// Returns true if this is a rate limit error (429)
        pub fn is_rate_limit_error(&self) -> bool {
            matches!(self, Error::RateLimit { .. })
        }

        /// Returns true if this error is retryable
        pub fn is_retryable(&self) -> bool {
            match self {
                Error::RateLimit { .. } => true,
                Error::Api { status_code, .. } => *status_code >= 500,
                Error::Http(e) => e.is_timeout() || e.is_connect(),
                _ => false,
            }
        }
    }

    /// Error detail for validation errors
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ErrorDetail {
        pub field: String,
        pub code: String,
        pub message: String,
    }
}

// =============================================================================
// Types
// =============================================================================

pub mod types {
    use super::*;

    /// Pagination information
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Pagination {
        pub page: u32,
        pub per_page: u32,
        pub total: u32,
        pub total_pages: u32,
    }

    /// Cursor-based pagination
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct CursorPagination {
        pub has_more: bool,
        pub next_cursor: Option<String>,
        pub prev_cursor: Option<String>,
    }

    /// List response with pagination
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ListResponse<T> {
        pub data: Vec<T>,
        #[serde(default)]
        pub pagination: Option<Pagination>,
    }

    /// Address
    #[derive(Debug, Clone, Default, Deserialize, Serialize)]
    pub struct Address {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub street: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub street2: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub city: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub postal_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub country: Option<String>,
    }

    // =========================================================================
    // Identity Types
    // =========================================================================

    /// User
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct User {
        pub id: String,
        pub email: String,
        pub email_verified: bool,
        #[serde(default)]
        pub profile: Option<UserProfile>,
        pub status: String,
        #[serde(default)]
        pub roles: Vec<String>,
        #[serde(default)]
        pub groups: Vec<GroupRef>,
        #[serde(default)]
        pub mfa: Option<MfaSettings>,
        #[serde(default)]
        pub metadata: HashMap<String, serde_json::Value>,
        pub last_login_at: Option<DateTime<Utc>>,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
    }

    /// User profile
    #[derive(Debug, Clone, Default, Deserialize, Serialize)]
    pub struct UserProfile {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub first_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub avatar_url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub phone: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub phone_verified: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub locale: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub timezone: Option<String>,
    }

    /// Group reference
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct GroupRef {
        pub id: String,
        pub name: String,
    }

    /// MFA settings
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct MfaSettings {
        pub enabled: bool,
        #[serde(default)]
        pub methods: Vec<String>,
    }

    /// Parameters for creating a user
    #[derive(Debug, Clone, Default, Serialize)]
    pub struct CreateUserParams {
        pub email: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub profile: Option<UserProfile>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metadata: Option<HashMap<String, serde_json::Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub send_welcome_email: Option<bool>,
    }

    impl CreateUserParams {
        pub fn builder() -> CreateUserParamsBuilder {
            CreateUserParamsBuilder::default()
        }
    }

    /// Builder for CreateUserParams
    #[derive(Debug, Clone, Default)]
    pub struct CreateUserParamsBuilder {
        params: CreateUserParams,
    }

    impl CreateUserParamsBuilder {
        pub fn email(mut self, email: impl Into<String>) -> Self {
            self.params.email = email.into();
            self
        }

        pub fn password(mut self, password: impl Into<String>) -> Self {
            self.params.password = Some(password.into());
            self
        }

        pub fn profile(mut self, profile: UserProfile) -> Self {
            self.params.profile = Some(profile);
            self
        }

        pub fn roles(mut self, roles: Vec<String>) -> Self {
            self.params.roles = Some(roles);
            self
        }

        pub fn send_welcome_email(mut self, send: bool) -> Self {
            self.params.send_welcome_email = Some(send);
            self
        }

        pub fn build(self) -> CreateUserParams {
            self.params
        }
    }

    /// Parameters for listing users
    #[derive(Debug, Clone, Default, Serialize)]
    pub struct ListUsersParams {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub page: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub per_page: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub search: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sort: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub order: Option<String>,
    }

    // =========================================================================
    // CRM Types
    // =========================================================================

    /// Contact
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Contact {
        pub id: String,
        #[serde(default)]
        pub first_name: Option<String>,
        #[serde(default)]
        pub last_name: Option<String>,
        pub email: String,
        #[serde(default)]
        pub phone: Option<String>,
        #[serde(default)]
        pub mobile: Option<String>,
        #[serde(default)]
        pub title: Option<String>,
        #[serde(default)]
        pub department: Option<String>,
        #[serde(default)]
        pub account: Option<AccountRef>,
        #[serde(default)]
        pub owner: Option<OwnerRef>,
        #[serde(default)]
        pub lead_source: Option<String>,
        #[serde(default)]
        pub lead_status: Option<String>,
        #[serde(default)]
        pub lead_score: Option<i32>,
        #[serde(default)]
        pub lifecycle_stage: Option<String>,
        #[serde(default)]
        pub address: Option<Address>,
        #[serde(default)]
        pub tags: Vec<String>,
        #[serde(default)]
        pub custom_fields: HashMap<String, serde_json::Value>,
        pub last_activity_at: Option<DateTime<Utc>>,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
    }

    /// Account reference
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct AccountRef {
        pub id: String,
        pub name: String,
    }

    /// Owner reference
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct OwnerRef {
        pub id: String,
        pub name: String,
    }

    /// Parameters for creating a contact
    #[derive(Debug, Clone, Default, Serialize)]
    pub struct CreateContactParams {
        pub email: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub first_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub phone: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mobile: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub company_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub lead_source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub owner_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub custom_fields: Option<HashMap<String, serde_json::Value>>,
    }

    impl CreateContactParams {
        pub fn builder() -> CreateContactParamsBuilder {
            CreateContactParamsBuilder::default()
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct CreateContactParamsBuilder {
        params: CreateContactParams,
    }

    impl CreateContactParamsBuilder {
        pub fn email(mut self, email: impl Into<String>) -> Self {
            self.params.email = email.into();
            self
        }

        pub fn first_name(mut self, name: impl Into<String>) -> Self {
            self.params.first_name = Some(name.into());
            self
        }

        pub fn last_name(mut self, name: impl Into<String>) -> Self {
            self.params.last_name = Some(name.into());
            self
        }

        pub fn company_name(mut self, name: impl Into<String>) -> Self {
            self.params.company_name = Some(name.into());
            self
        }

        pub fn build(self) -> CreateContactParams {
            self.params
        }
    }

    /// Parameters for listing contacts
    #[derive(Debug, Clone, Default, Serialize)]
    pub struct ListContactsParams {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub page: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub per_page: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub search: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub owner_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub account_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sort: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub order: Option<String>,
    }

    // =========================================================================
    // Payment Types
    // =========================================================================

    /// Payment intent
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct PaymentIntent {
        pub id: String,
        pub amount: i64,
        pub currency: String,
        pub status: String,
        #[serde(default)]
        pub client_secret: Option<String>,
        #[serde(default)]
        pub customer_id: Option<String>,
        #[serde(default)]
        pub payment_method_id: Option<String>,
        #[serde(default)]
        pub payment_method: Option<PaymentMethod>,
        pub capture_method: String,
        #[serde(default)]
        pub amount_capturable: Option<i64>,
        #[serde(default)]
        pub amount_received: Option<i64>,
        #[serde(default)]
        pub next_action: Option<NextAction>,
        #[serde(default)]
        pub charges: Vec<Charge>,
        #[serde(default)]
        pub metadata: HashMap<String, serde_json::Value>,
        #[serde(default)]
        pub receipt_email: Option<String>,
        pub created_at: DateTime<Utc>,
    }

    /// Payment method
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct PaymentMethod {
        pub id: String,
        #[serde(rename = "type")]
        pub method_type: String,
        #[serde(default)]
        pub card: Option<CardDetail>,
    }

    /// Card details
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct CardDetail {
        pub brand: String,
        pub last4: String,
        pub exp_month: u32,
        pub exp_year: u32,
    }

    /// Next action for payment
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct NextAction {
        #[serde(rename = "type")]
        pub action_type: String,
        #[serde(default)]
        pub redirect_to_url: Option<RedirectToUrl>,
    }

    /// Redirect URL info
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct RedirectToUrl {
        pub url: String,
        pub return_url: String,
    }

    /// Charge
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Charge {
        pub id: String,
        pub amount: i64,
        pub status: String,
        #[serde(default)]
        pub receipt_url: Option<String>,
    }

    /// Parameters for creating a payment intent
    #[derive(Debug, Clone, Default, Serialize)]
    pub struct CreatePaymentIntentParams {
        pub amount: i64,
        pub currency: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub customer_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub payment_method_types: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub capture_method: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metadata: Option<HashMap<String, serde_json::Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub receipt_email: Option<String>,
    }

    impl CreatePaymentIntentParams {
        pub fn new(amount: i64, currency: impl Into<String>) -> Self {
            Self {
                amount,
                currency: currency.into(),
                ..Default::default()
            }
        }
    }

    /// Subscription
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Subscription {
        pub id: String,
        pub customer_id: String,
        pub plan: SubscriptionPlan,
        pub status: String,
        pub current_period_start: DateTime<Utc>,
        pub current_period_end: DateTime<Utc>,
        #[serde(default)]
        pub trial_start: Option<DateTime<Utc>>,
        #[serde(default)]
        pub trial_end: Option<DateTime<Utc>>,
        pub cancel_at_period_end: bool,
        #[serde(default)]
        pub canceled_at: Option<DateTime<Utc>>,
        #[serde(default)]
        pub cancel_at: Option<DateTime<Utc>>,
        #[serde(default)]
        pub default_payment_method_id: Option<String>,
        #[serde(default)]
        pub metadata: HashMap<String, serde_json::Value>,
        pub created_at: DateTime<Utc>,
    }

    /// Subscription plan
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct SubscriptionPlan {
        pub id: String,
        pub name: String,
        pub amount: i64,
        pub currency: String,
        pub interval: String,
        pub interval_count: u32,
    }

    /// Refund
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Refund {
        pub id: String,
        pub payment_intent_id: String,
        #[serde(default)]
        pub charge_id: Option<String>,
        pub amount: i64,
        pub currency: String,
        pub status: String,
        #[serde(default)]
        pub reason: Option<String>,
        #[serde(default)]
        pub metadata: HashMap<String, serde_json::Value>,
        pub created_at: DateTime<Utc>,
    }
}

// =============================================================================
// HTTP Client
// =============================================================================

/// Configuration for the OpenSASE client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub base_url: String,
    pub api_key: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: String::new(),
            timeout: DEFAULT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay: Duration::from_secs(1),
        }
    }
}

/// OpenSASE API client
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    config: ClientConfig,
    http: reqwest::Client,
}

impl Client {
    /// Create a new client with the given API key
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_config(ClientConfig {
            api_key: api_key.into(),
            ..Default::default()
        })
    }

    /// Create a new client with custom configuration
    pub fn with_config(config: ClientConfig) -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", config.api_key))
                .expect("Invalid API key"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&format!("opensase-rust/{}", VERSION))
                .expect("Invalid user agent"),
        );

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(config.timeout)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            inner: Arc::new(ClientInner { config, http }),
        }
    }

    /// Get the identity service
    pub fn identity(&self) -> services::IdentityService {
        services::IdentityService::new(self.clone())
    }

    /// Get the CRM service
    pub fn crm(&self) -> services::CrmService {
        services::CrmService::new(self.clone())
    }

    /// Get the payments service
    pub fn payments(&self) -> services::PaymentsService {
        services::PaymentsService::new(self.clone())
    }

    /// Make a GET request
    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        params: Option<&[(&str, &str)]>,
    ) -> Result<T> {
        self.request(reqwest::Method::GET, path, None::<()>, params, None)
            .await
    }

    /// Make a POST request
    pub(crate) async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: B,
        idempotency_key: Option<&str>,
    ) -> Result<T> {
        self.request(reqwest::Method::POST, path, Some(body), None, idempotency_key)
            .await
    }

    /// Make a PATCH request
    pub(crate) async fn patch<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: B,
    ) -> Result<T> {
        self.request(reqwest::Method::PATCH, path, Some(body), None, None)
            .await
    }

    /// Make a DELETE request
    pub(crate) async fn delete(&self, path: &str) -> Result<()> {
        self.request::<(), ()>(reqwest::Method::DELETE, path, None, None, None)
            .await
            .map(|_| ())
    }

    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<B>,
        params: Option<&[(&str, &str)]>,
        idempotency_key: Option<&str>,
    ) -> Result<T> {
        let mut url = Url::parse(&format!("{}{}", self.inner.config.base_url, path))?;

        if let Some(params) = params {
            for (key, value) in params {
                url.query_pairs_mut().append_pair(key, value);
            }
        }

        let mut last_error = None;

        for attempt in 0..=self.inner.config.max_retries {
            let mut request = self.inner.http.request(method.clone(), url.clone());

            if let Some(ref body) = body {
                request = request.json(body);
            }

            if let Some(key) = idempotency_key {
                request = request.header("Idempotency-Key", key);
            }

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    last_error = Some(Error::Http(e));
                    if attempt < self.inner.config.max_retries {
                        tokio::time::sleep(self.inner.config.retry_delay * (1 << attempt)).await;
                        continue;
                    }
                    return Err(last_error.unwrap());
                }
            };

            let status = response.status();
            let request_id = response
                .headers()
                .get("X-Request-ID")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            if status == StatusCode::NO_CONTENT {
                return Ok(serde_json::from_str("null")?);
            }

            let body_bytes = response.bytes().await?;

            if status.is_success() {
                #[derive(Deserialize)]
                struct ApiResponse<T> {
                    data: Option<T>,
                }

                // Try to parse with data wrapper first
                if let Ok(resp) = serde_json::from_slice::<ApiResponse<T>>(&body_bytes) {
                    if let Some(data) = resp.data {
                        return Ok(data);
                    }
                }

                // Fall back to parsing directly
                return Ok(serde_json::from_slice(&body_bytes)?);
            }

            // Handle errors
            if status == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30);

                let error = Error::RateLimit {
                    retry_after,
                    limit: 0,
                    remaining: 0,
                    request_id,
                };

                if attempt < self.inner.config.max_retries {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_secs(retry_after)).await;
                    continue;
                }

                return Err(error);
            }

            // Parse error response
            #[derive(Deserialize)]
            struct ErrorResponse {
                error: ErrorBody,
            }

            #[derive(Deserialize)]
            struct ErrorBody {
                code: String,
                message: String,
                #[serde(default)]
                details: Vec<ErrorDetail>,
            }

            let error = if let Ok(err_resp) = serde_json::from_slice::<ErrorResponse>(&body_bytes) {
                Error::Api {
                    code: err_resp.error.code,
                    message: err_resp.error.message,
                    status_code: status.as_u16(),
                    request_id,
                    details: err_resp.error.details,
                }
            } else {
                Error::Api {
                    code: "unknown_error".to_string(),
                    message: String::from_utf8_lossy(&body_bytes).to_string(),
                    status_code: status.as_u16(),
                    request_id,
                    details: vec![],
                }
            };

            if error.is_retryable() && attempt < self.inner.config.max_retries {
                last_error = Some(error);
                tokio::time::sleep(self.inner.config.retry_delay * (1 << attempt)).await;
                continue;
            }

            return Err(error);
        }

        Err(last_error.unwrap_or_else(|| Error::Config("Request failed".to_string())))
    }
}

// =============================================================================
// Services
// =============================================================================

pub mod services {
    use super::*;

    // Identity Service
    pub struct IdentityService {
        client: Client,
    }

    impl IdentityService {
        pub(crate) fn new(client: Client) -> Self {
            Self { client }
        }

        pub fn users(&self) -> UsersService {
            UsersService {
                client: self.client.clone(),
            }
        }

        pub fn auth(&self) -> AuthService {
            AuthService {
                client: self.client.clone(),
            }
        }

        pub fn groups(&self) -> GroupsService {
            GroupsService {
                client: self.client.clone(),
            }
        }
    }

    pub struct UsersService {
        client: Client,
    }

    impl UsersService {
        pub async fn list(&self, params: ListUsersParams) -> Result<ListResponse<User>> {
            let mut query_params = vec![];
            if let Some(page) = params.page {
                query_params.push(("page", page.to_string()));
            }
            if let Some(per_page) = params.per_page {
                query_params.push(("per_page", per_page.to_string()));
            }
            if let Some(search) = params.search {
                query_params.push(("search", search));
            }

            let params_refs: Vec<(&str, &str)> = query_params
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();

            self.client
                .get("/identity/users", Some(&params_refs))
                .await
        }

        pub async fn create(&self, params: CreateUserParams) -> Result<User> {
            self.client.post("/identity/users", params, None).await
        }

        pub async fn get(&self, user_id: &str) -> Result<User> {
            self.client
                .get(&format!("/identity/users/{}", user_id), None)
                .await
        }

        pub async fn delete(&self, user_id: &str) -> Result<()> {
            self.client
                .delete(&format!("/identity/users/{}", user_id))
                .await
        }
    }

    pub struct AuthService {
        client: Client,
    }

    pub struct GroupsService {
        client: Client,
    }

    // CRM Service
    pub struct CrmService {
        client: Client,
    }

    impl CrmService {
        pub(crate) fn new(client: Client) -> Self {
            Self { client }
        }

        pub fn contacts(&self) -> ContactsService {
            ContactsService {
                client: self.client.clone(),
            }
        }

        pub fn deals(&self) -> DealsService {
            DealsService {
                client: self.client.clone(),
            }
        }
    }

    pub struct ContactsService {
        client: Client,
    }

    impl ContactsService {
        pub async fn list(&self, params: ListContactsParams) -> Result<ListResponse<Contact>> {
            let mut query_params = vec![];
            if let Some(page) = params.page {
                query_params.push(("page", page.to_string()));
            }
            if let Some(per_page) = params.per_page {
                query_params.push(("per_page", per_page.to_string()));
            }
            if let Some(search) = params.search {
                query_params.push(("search", search));
            }

            let params_refs: Vec<(&str, &str)> = query_params
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();

            self.client
                .get("/crm/contacts", Some(&params_refs))
                .await
        }

        pub async fn create(&self, params: CreateContactParams) -> Result<Contact> {
            self.client.post("/crm/contacts", params, None).await
        }

        pub async fn get(&self, contact_id: &str) -> Result<Contact> {
            self.client
                .get(&format!("/crm/contacts/{}", contact_id), None)
                .await
        }

        pub async fn delete(&self, contact_id: &str) -> Result<()> {
            self.client
                .delete(&format!("/crm/contacts/{}", contact_id))
                .await
        }
    }

    pub struct DealsService {
        client: Client,
    }

    // Payments Service
    pub struct PaymentsService {
        client: Client,
    }

    impl PaymentsService {
        pub(crate) fn new(client: Client) -> Self {
            Self { client }
        }

        pub fn intents(&self) -> PaymentIntentsService {
            PaymentIntentsService {
                client: self.client.clone(),
            }
        }

        pub fn subscriptions(&self) -> SubscriptionsService {
            SubscriptionsService {
                client: self.client.clone(),
            }
        }

        pub fn refunds(&self) -> RefundsService {
            RefundsService {
                client: self.client.clone(),
            }
        }
    }

    pub struct PaymentIntentsService {
        client: Client,
    }

    impl PaymentIntentsService {
        pub async fn create(
            &self,
            params: CreatePaymentIntentParams,
            idempotency_key: Option<&str>,
        ) -> Result<PaymentIntent> {
            self.client
                .post("/payments/intents", params, idempotency_key)
                .await
        }

        pub async fn get(&self, intent_id: &str) -> Result<PaymentIntent> {
            self.client
                .get(&format!("/payments/intents/{}", intent_id), None)
                .await
        }

        pub async fn confirm(
            &self,
            intent_id: &str,
            payment_method_id: &str,
            return_url: Option<&str>,
            idempotency_key: Option<&str>,
        ) -> Result<PaymentIntent> {
            #[derive(Serialize)]
            struct ConfirmParams<'a> {
                payment_method_id: &'a str,
                #[serde(skip_serializing_if = "Option::is_none")]
                return_url: Option<&'a str>,
            }

            self.client
                .post(
                    &format!("/payments/intents/{}/confirm", intent_id),
                    ConfirmParams {
                        payment_method_id,
                        return_url,
                    },
                    idempotency_key,
                )
                .await
        }

        pub async fn capture(
            &self,
            intent_id: &str,
            amount_to_capture: Option<i64>,
            idempotency_key: Option<&str>,
        ) -> Result<PaymentIntent> {
            #[derive(Serialize)]
            struct CaptureParams {
                #[serde(skip_serializing_if = "Option::is_none")]
                amount_to_capture: Option<i64>,
            }

            self.client
                .post(
                    &format!("/payments/intents/{}/capture", intent_id),
                    CaptureParams { amount_to_capture },
                    idempotency_key,
                )
                .await
        }

        pub async fn cancel(
            &self,
            intent_id: &str,
            reason: Option<&str>,
        ) -> Result<PaymentIntent> {
            #[derive(Serialize)]
            struct CancelParams<'a> {
                #[serde(skip_serializing_if = "Option::is_none")]
                cancellation_reason: Option<&'a str>,
            }

            self.client
                .post(
                    &format!("/payments/intents/{}/cancel", intent_id),
                    CancelParams {
                        cancellation_reason: reason,
                    },
                    None,
                )
                .await
        }
    }

    pub struct SubscriptionsService {
        client: Client,
    }

    pub struct RefundsService {
        client: Client,
    }
}

// =============================================================================
// Webhook Utilities
// =============================================================================

pub mod webhooks {
    use super::*;

    /// Verify webhook signature
    pub fn verify_signature(
        payload: &[u8],
        signature: &str,
        timestamp: &str,
        secret: &str,
        tolerance_secs: i64,
    ) -> Result<bool> {
        // Check timestamp tolerance
        let ts: i64 = timestamp
            .parse()
            .map_err(|_| Error::Config("Invalid timestamp".to_string()))?;

        let now = chrono::Utc::now().timestamp();
        if (now - ts).abs() > tolerance_secs {
            return Err(Error::TimestampOutsideTolerance);
        }

        // Compute expected signature
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));

        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| Error::InvalidSignature)?;
        mac.update(signed_payload.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        // Parse and compare signatures
        for part in signature.split(',') {
            let parts: Vec<&str> = part.split('=').collect();
            if parts.len() == 2 && parts[0] == "v1" {
                return Ok(parts[1] == expected_sig);
            }
        }

        Ok(false)
    }

    /// Webhook event
    #[derive(Debug, Clone, Deserialize)]
    pub struct WebhookEvent {
        pub id: String,
        pub object: String,
        pub api_version: String,
        pub created: i64,
        #[serde(rename = "type")]
        pub event_type: String,
        pub livemode: bool,
        pub pending_webhooks: u32,
        pub request: Option<WebhookRequest>,
        pub data: serde_json::Value,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct WebhookRequest {
        pub id: Option<String>,
        pub idempotency_key: Option<String>,
    }

    /// Construct and verify a webhook event
    pub fn construct_event(
        payload: &[u8],
        signature: &str,
        timestamp: &str,
        secret: &str,
    ) -> Result<WebhookEvent> {
        if !verify_signature(payload, signature, timestamp, secret, 300)? {
            return Err(Error::InvalidSignature);
        }

        Ok(serde_json::from_slice(payload)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_client() {
        let client = Client::new("test_api_key");
        assert!(client.inner.config.api_key == "test_api_key");
    }

    #[test]
    fn test_create_user_params_builder() {
        let params = CreateUserParams::builder()
            .email("test@example.com")
            .password("password123")
            .send_welcome_email(true)
            .build();

        assert_eq!(params.email, "test@example.com");
        assert_eq!(params.password, Some("password123".to_string()));
        assert_eq!(params.send_welcome_email, Some(true));
    }

    #[test]
    fn test_webhook_signature_verification() {
        let payload = b"test payload";
        let secret = "test_secret";
        let timestamp = chrono::Utc::now().timestamp().to_string();

        // Compute valid signature
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let valid_sig = format!("v1={}", hex::encode(mac.finalize().into_bytes()));

        let result = webhooks::verify_signature(payload, &valid_sig, &timestamp, secret, 300);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
