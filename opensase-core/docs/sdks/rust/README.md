# OpenSASE Rust SDK

Official Rust SDK for the OpenSASE Platform API.

[![Crates.io](https://img.shields.io/crates/v/opensase.svg)](https://crates.io/crates/opensase)
[![Documentation](https://docs.rs/opensase/badge.svg)](https://docs.rs/opensase)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🚀 **Async-first** - Built on Tokio for high-performance async operations
- 🔒 **Type-safe** - Strong typing with builder patterns for all API calls
- 🔄 **Automatic retries** - Exponential backoff with configurable retry logic
- 📦 **Zero-copy deserialization** - Efficient JSON parsing with Serde
- 🛡️ **Error handling** - Rich error types with detailed information

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
opensase = "1.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use opensase::{Client, CreateUserParams, CreateContactParams, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("os_live_abc123...");

    // Create a user
    let user = client.identity().users().create(
        CreateUserParams::builder()
            .email("john@example.com")
            .password("secure_password")
            .send_welcome_email(true)
            .build()
    ).await?;

    println!("Created user: {}", user.id);

    // List contacts
    let contacts = client.crm().contacts().list(
        ListContactsParams::default()
    ).await?;

    for contact in contacts.data {
        println!("Contact: {} - {}", contact.id, contact.email);
    }

    Ok(())
}
```

## Configuration

```rust
use opensase::{Client, ClientConfig};
use std::time::Duration;

let client = Client::with_config(ClientConfig {
    api_key: "os_live_abc123...".to_string(),
    base_url: "https://api.staging.opensase.billyronks.io/v1".to_string(),
    timeout: Duration::from_secs(60),
    max_retries: 5,
    retry_delay: Duration::from_secs(2),
});
```

## Services

### Identity

```rust
// Users
let user = client.identity().users().create(
    CreateUserParams::builder()
        .email("john@example.com")
        .build()
).await?;

let user = client.identity().users().get("user_abc123").await?;
client.identity().users().delete("user_abc123").await?;

// List with pagination
let users = client.identity().users().list(ListUsersParams {
    page: Some(1),
    per_page: Some(20),
    search: Some("john".to_string()),
    ..Default::default()
}).await?;
```

### CRM

```rust
// Contacts
let contact = client.crm().contacts().create(
    CreateContactParams::builder()
        .email("jane@example.com")
        .first_name("Jane")
        .last_name("Smith")
        .company_name("Acme Corp")
        .build()
).await?;

let contacts = client.crm().contacts().list(ListContactsParams {
    search: Some("acme".to_string()),
    status: Some("qualified".to_string()),
    ..Default::default()
}).await?;
```

### Payments

```rust
use opensase::CreatePaymentIntentParams;

// Create payment intent
let payment = client.payments().intents().create(
    CreatePaymentIntentParams::new(9999, "usd"),
    Some("idempotency_key_123"), // Optional idempotency key
).await?;

// Confirm with payment method
let confirmed = client.payments().intents().confirm(
    &payment.id,
    "pm_card_xyz",
    Some("https://yourapp.com/return"),
    None,
).await?;

// Handle 3DS
if confirmed.status == "requires_action" {
    if let Some(next_action) = confirmed.next_action {
        if let Some(redirect) = next_action.redirect_to_url {
            println!("Redirect user to: {}", redirect.url);
        }
    }
}

// Capture
let captured = client.payments().intents().capture(
    &payment.id,
    None, // Full capture
    None,
).await?;

// Cancel
let canceled = client.payments().intents().cancel(
    &payment.id,
    Some("requested_by_customer"),
).await?;
```

## Error Handling

```rust
use opensase::{Client, Error, Result};

async fn example() -> Result<()> {
    let client = Client::new("os_live_abc123...");
    
    match client.crm().contacts().get("invalid_id").await {
        Ok(contact) => println!("Found: {}", contact.email),
        Err(Error::Api { code, message, status_code, request_id, details }) => {
            eprintln!("API Error ({}): {} - {}", status_code, code, message);
            if let Some(rid) = request_id {
                eprintln!("Request ID: {}", rid);
            }
            for detail in details {
                eprintln!("  - {}: {} ({})", detail.field, detail.message, detail.code);
            }
        }
        Err(Error::RateLimit { retry_after, .. }) => {
            eprintln!("Rate limited. Retry after {} seconds", retry_after);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
    
    Ok(())
}

// Using error type methods
fn handle_error(err: Error) {
    if err.is_validation_error() {
        println!("Validation failed");
    } else if err.is_not_found_error() {
        println!("Resource not found");
    } else if err.is_retryable() {
        println!("Can retry this request");
    }
}
```

## Webhooks

```rust
use opensase::webhooks::{construct_event, verify_signature};
use axum::{
    extract::RawBody,
    http::HeaderMap,
    response::Json,
};

async fn webhook_handler(
    headers: HeaderMap,
    body: RawBody,
) -> Json<serde_json::Value> {
    let signature = headers
        .get("x-opensase-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    let timestamp = headers
        .get("x-opensase-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    let payload = hyper::body::to_bytes(body).await.unwrap();
    
    match construct_event(&payload, signature, timestamp, "whsec_your_secret") {
        Ok(event) => {
            match event.event_type.as_str() {
                "payment_intent.succeeded" => {
                    // Handle successful payment
                }
                "customer.subscription.created" => {
                    // Handle new subscription
                }
                _ => {}
            }
            Json(serde_json::json!({ "received": true }))
        }
        Err(e) => {
            eprintln!("Webhook error: {}", e);
            Json(serde_json::json!({ "error": "Invalid signature" }))
        }
    }
}
```

## Streaming / Pagination

```rust
use futures::StreamExt;

// Manual pagination
let mut page = 1;
loop {
    let response = client.crm().contacts().list(ListContactsParams {
        page: Some(page),
        per_page: Some(100),
        ..Default::default()
    }).await?;
    
    for contact in response.data {
        println!("{}", contact.email);
    }
    
    if let Some(pagination) = response.pagination {
        if page >= pagination.total_pages {
            break;
        }
    } else {
        break;
    }
    page += 1;
}
```

## Blocking API

Enable the `blocking` feature for synchronous operations:

```toml
[dependencies]
opensase = { version = "1.0", features = ["blocking"] }
```

```rust
use opensase::blocking::Client;

fn main() -> opensase::Result<()> {
    let client = Client::new("os_live_abc123...");
    
    let user = client.identity().users().get("user_abc123")?;
    println!("User: {}", user.email);
    
    Ok(())
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use opensase::{Client, CreateUserParams};
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn test_create_user() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("POST"))
            .and(path("/identity/users"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "data": {
                    "id": "user_test123",
                    "email": "test@example.com",
                    "email_verified": false,
                    "status": "active",
                    "roles": [],
                    "groups": [],
                    "metadata": {},
                    "created_at": "2024-01-15T12:00:00Z",
                    "updated_at": "2024-01-15T12:00:00Z"
                }
            })))
            .mount(&mock_server)
            .await;
        
        let client = Client::with_config(opensase::ClientConfig {
            api_key: "test_key".to_string(),
            base_url: mock_server.uri(),
            ..Default::default()
        });
        
        let user = client.identity().users().create(
            CreateUserParams::builder()
                .email("test@example.com")
                .build()
        ).await.unwrap();
        
        assert_eq!(user.id, "user_test123");
        assert_eq!(user.email, "test@example.com");
    }
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.opensase.billyronks.io
- API Reference: https://docs.rs/opensase
- Issues: https://github.com/billyronks/opensase-rust-sdk/issues
