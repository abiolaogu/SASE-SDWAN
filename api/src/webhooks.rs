//! Webhook Delivery System

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use uuid::Uuid;

/// Webhook manager
pub struct WebhookDelivery {
    subscriptions: Arc<RwLock<HashMap<Uuid, WebhookConfig>>>,
    queue: Arc<RwLock<Vec<WebhookEvent>>>,
    dead_letter: Arc<RwLock<Vec<DeadLetter>>>,
}

impl WebhookDelivery {
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            queue: Arc::new(RwLock::new(Vec::new())),
            dead_letter: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Subscribe to events
    pub fn subscribe(&self, config: WebhookConfig) -> Uuid {
        let id = config.id;
        self.subscriptions.write().insert(id, config);
        id
    }

    /// Publish event to all subscribers
    pub fn publish(&self, event: Event) {
        let subs = self.subscriptions.read();
        for (id, config) in subs.iter() {
            if config.enabled && config.events.contains(&event.event_type) {
                self.queue.write().push(WebhookEvent {
                    id: Uuid::new_v4(),
                    subscription_id: *id,
                    event: event.clone(),
                    attempt: 0,
                    next_attempt: chrono::Utc::now(),
                });
            }
        }
    }

    /// Process delivery queue
    pub async fn process(&self) {
        let events: Vec<_> = {
            let mut queue = self.queue.write();
            queue.drain(..).collect()
        };

        for mut event in events {
            let config = {
                let subs = self.subscriptions.read();
                subs.get(&event.subscription_id).cloned()
            };

            if let Some(config) = config {
                match self.deliver(&config, &event.event).await {
                    Ok(_) => {
                        tracing::info!("Webhook delivered: {}", event.id);
                    }
                    Err(e) => {
                        event.attempt += 1;
                        if event.attempt < config.retry_policy.max_retries {
                            let delay = config.retry_policy.base_delay_secs * 2u64.pow(event.attempt);
                            event.next_attempt = chrono::Utc::now() + chrono::Duration::seconds(delay as i64);
                            self.queue.write().push(event);
                        } else {
                            self.dead_letter.write().push(DeadLetter {
                                event,
                                error: e,
                                failed_at: chrono::Utc::now(),
                            });
                        }
                    }
                }
            }
        }
    }

    async fn deliver(&self, config: &WebhookConfig, event: &Event) -> Result<(), String> {
        let payload = serde_json::to_string(event).map_err(|e| e.to_string())?;
        let signature = self.sign(&payload, &config.secret);

        let client = reqwest::Client::new();
        let resp = client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .header("X-OpenSASE-Signature", signature)
            .header("X-OpenSASE-Event", &event.event_type.to_string())
            .body(payload)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", resp.status()))
        }
    }

    fn sign(&self, payload: &str, secret: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut mac = Sha256::new();
        mac.update(secret.as_bytes());
        mac.update(payload.as_bytes());
        format!("sha256={}", hex::encode(mac.finalize()))
    }
}

impl Default for WebhookDelivery {
    fn default() -> Self { Self::new() }
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: Uuid,
    pub url: String,
    pub events: Vec<EventType>,
    pub secret: String,
    pub retry_policy: RetryPolicy,
    pub enabled: bool,
}

/// Retry policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_retries: 5, base_delay_secs: 60 }
    }
}

/// Event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    SiteStatusChanged,
    SecurityAlert,
    PolicyChanged,
    UserActivity,
    SystemHealth,
    TunnelStatusChanged,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SiteStatusChanged => write!(f, "site.status_changed"),
            Self::SecurityAlert => write!(f, "security.alert"),
            Self::PolicyChanged => write!(f, "policy.changed"),
            Self::UserActivity => write!(f, "user.activity"),
            Self::SystemHealth => write!(f, "system.health"),
            Self::TunnelStatusChanged => write!(f, "tunnel.status_changed"),
        }
    }
}

/// Event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub event_type: EventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tenant_id: Uuid,
    pub data: serde_json::Value,
}

/// Queued webhook event
#[derive(Debug, Clone)]
struct WebhookEvent {
    id: Uuid,
    subscription_id: Uuid,
    event: Event,
    attempt: u32,
    next_attempt: chrono::DateTime<chrono::Utc>,
}

/// Dead letter entry
#[derive(Debug, Clone)]
struct DeadLetter {
    event: WebhookEvent,
    error: String,
    failed_at: chrono::DateTime<chrono::Utc>,
}
