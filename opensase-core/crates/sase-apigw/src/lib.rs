//! OpenSASE API Gateway (OSAG)
//!
//! Kong-based API Gateway providing:
//! - API authentication (OAuth2, JWT, API keys, mTLS)
//! - Rate limiting and quota management
//! - Request/response transformation
//! - API versioning and routing
//! - DDoS protection for APIs
//! - API analytics and monitoring
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    OpenSASE API Gateway (OSAG)                  │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │                     Kong Gateway                          │  │
//! │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │  │
//! │  │  │  Auth   │ │  Rate   │ │ Transform│ │Analytics│        │  │
//! │  │  │ Plugins │ │ Limiter │ │ Plugins │ │ Plugins │        │  │
//! │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘        │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! │                              │                                   │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │                   OSAG Control Plane                      │  │
//! │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │  │
//! │  │  │ Service │ │  Route  │ │Consumer │ │ Plugin  │        │  │
//! │  │  │ Manager │ │ Manager │ │ Manager │ │ Manager │        │  │
//! │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘        │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! │                              │                                   │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │                    Upstream Services                      │  │
//! │  │   OpenSASE APIs │ Customer APIs │ Third-Party APIs       │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub mod kong;
pub mod auth;
pub mod ratelimit;
pub mod transform;
pub mod analytics;
pub mod routing;
pub mod ddos;

// Re-exports
pub use kong::KongClient;
pub use auth::{AuthManager, AuthMethod};
pub use ratelimit::{RateLimiter, RateLimitPolicy};

// =============================================================================
// Core Types
// =============================================================================

/// API Gateway configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Kong Admin API URL
    pub kong_admin_url: String,
    /// Kong Admin API key (optional)
    pub kong_admin_key: Option<String>,
    /// Workspace (Kong Enterprise)
    pub workspace: Option<String>,
    /// Default rate limit
    pub default_rate_limit: RateLimitConfig,
    /// Authentication settings
    pub auth: AuthConfig,
    /// Analytics settings
    pub analytics: AnalyticsConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub requests_per_day: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            requests_per_minute: 1000,
            requests_per_hour: 10000,
            requests_per_day: 100000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_expiry_secs: u64,
    pub api_key_header: String,
    pub oauth2_enabled: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: String::new(),
            jwt_issuer: "opensase".to_string(),
            jwt_audience: "opensase-api".to_string(),
            jwt_expiry_secs: 3600,
            api_key_header: "X-API-Key".to_string(),
            oauth2_enabled: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    pub enabled: bool,
    pub sample_rate: f32,
    pub retention_days: u32,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: 1.0,
            retention_days: 30,
        }
    }
}

// =============================================================================
// Kong Entities
// =============================================================================

/// Kong Service representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    pub id: Option<String>,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
    pub retries: Option<u32>,
    pub connect_timeout: Option<u32>,
    pub write_timeout: Option<u32>,
    pub read_timeout: Option<u32>,
    pub tags: Option<Vec<String>>,
    pub enabled: bool,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

impl Service {
    pub fn new(name: &str, host: &str, port: u16) -> Self {
        Self {
            id: None,
            name: name.to_string(),
            protocol: "http".to_string(),
            host: host.to_string(),
            port,
            path: None,
            retries: Some(5),
            connect_timeout: Some(60000),
            write_timeout: Some(60000),
            read_timeout: Some(60000),
            tags: None,
            enabled: true,
            created_at: None,
            updated_at: None,
        }
    }
    
    pub fn https(mut self) -> Self {
        self.protocol = "https".to_string();
        self
    }
    
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }
    
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }
}

/// Kong Route representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Route {
    pub id: Option<String>,
    pub name: String,
    pub protocols: Vec<String>,
    pub methods: Option<Vec<String>>,
    pub hosts: Option<Vec<String>>,
    pub paths: Option<Vec<String>>,
    pub headers: Option<HashMap<String, Vec<String>>>,
    pub strip_path: bool,
    pub preserve_host: bool,
    pub service: Option<ServiceRef>,
    pub tags: Option<Vec<String>>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceRef {
    pub id: String,
}

impl Route {
    pub fn new(name: &str, service_id: &str) -> Self {
        Self {
            id: None,
            name: name.to_string(),
            protocols: vec!["http".to_string(), "https".to_string()],
            methods: None,
            hosts: None,
            paths: None,
            headers: None,
            strip_path: true,
            preserve_host: false,
            service: Some(ServiceRef { id: service_id.to_string() }),
            tags: None,
            created_at: None,
            updated_at: None,
        }
    }
    
    pub fn with_paths(mut self, paths: Vec<String>) -> Self {
        self.paths = Some(paths);
        self
    }
    
    pub fn with_hosts(mut self, hosts: Vec<String>) -> Self {
        self.hosts = Some(hosts);
        self
    }
    
    pub fn with_methods(mut self, methods: Vec<String>) -> Self {
        self.methods = Some(methods);
        self
    }
}

/// Kong Consumer representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Consumer {
    pub id: Option<String>,
    pub username: String,
    pub custom_id: Option<String>,
    pub tags: Option<Vec<String>>,
    pub created_at: Option<i64>,
}

impl Consumer {
    pub fn new(username: &str) -> Self {
        Self {
            id: None,
            username: username.to_string(),
            custom_id: None,
            tags: None,
            created_at: None,
        }
    }
    
    pub fn with_custom_id(mut self, custom_id: &str) -> Self {
        self.custom_id = Some(custom_id.to_string());
        self
    }
}

/// Kong Plugin representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plugin {
    pub id: Option<String>,
    pub name: String,
    pub service: Option<ServiceRef>,
    pub route: Option<RouteRef>,
    pub consumer: Option<ConsumerRef>,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub protocols: Vec<String>,
    pub tags: Option<Vec<String>>,
    pub created_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteRef {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsumerRef {
    pub id: String,
}

impl Plugin {
    pub fn new(name: &str, config: serde_json::Value) -> Self {
        Self {
            id: None,
            name: name.to_string(),
            service: None,
            route: None,
            consumer: None,
            config,
            enabled: true,
            protocols: vec!["http".to_string(), "https".to_string()],
            tags: None,
            created_at: None,
        }
    }
    
    pub fn for_service(mut self, service_id: &str) -> Self {
        self.service = Some(ServiceRef { id: service_id.to_string() });
        self
    }
    
    pub fn for_route(mut self, route_id: &str) -> Self {
        self.route = Some(RouteRef { id: route_id.to_string() });
        self
    }
    
    pub fn for_consumer(mut self, consumer_id: &str) -> Self {
        self.consumer = Some(ConsumerRef { id: consumer_id.to_string() });
        self
    }
}

// =============================================================================
// API Gateway Manager
// =============================================================================

/// Main API Gateway manager
pub struct ApiGateway {
    config: GatewayConfig,
    kong: kong::KongClient,
    auth_manager: auth::AuthManager,
    rate_limiter: ratelimit::RateLimiter,
    analytics: analytics::AnalyticsCollector,
}

impl ApiGateway {
    /// Create new API Gateway instance
    pub async fn new(config: GatewayConfig) -> Result<Self, GatewayError> {
        let kong = kong::KongClient::new(&config.kong_admin_url, config.kong_admin_key.clone())?;
        let auth_manager = auth::AuthManager::new(config.auth.clone());
        let rate_limiter = ratelimit::RateLimiter::new(config.default_rate_limit.clone());
        let analytics = analytics::AnalyticsCollector::new(config.analytics.clone());
        
        Ok(Self {
            config,
            kong,
            auth_manager,
            rate_limiter,
            analytics,
        })
    }
    
    /// Register a new API service
    pub async fn register_service(&self, service: Service) -> Result<Service, GatewayError> {
        self.kong.create_service(service).await
    }
    
    /// Register a route for a service
    pub async fn register_route(&self, route: Route) -> Result<Route, GatewayError> {
        self.kong.create_route(route).await
    }
    
    /// Register a consumer
    pub async fn register_consumer(&self, consumer: Consumer) -> Result<Consumer, GatewayError> {
        self.kong.create_consumer(consumer).await
    }
    
    /// Enable a plugin
    pub async fn enable_plugin(&self, plugin: Plugin) -> Result<Plugin, GatewayError> {
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable JWT authentication for a service
    pub async fn enable_jwt_auth(&self, service_id: &str) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("jwt", serde_json::json!({
            "claims_to_verify": ["exp"],
            "key_claim_name": "iss",
            "secret_is_base64": false,
            "run_on_preflight": true
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable API key authentication for a service
    pub async fn enable_key_auth(&self, service_id: &str) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("key-auth", serde_json::json!({
            "key_names": ["apikey", "X-API-Key"],
            "key_in_body": false,
            "key_in_header": true,
            "key_in_query": true,
            "hide_credentials": true
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable OAuth2 authentication for a service
    pub async fn enable_oauth2(&self, service_id: &str) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("oauth2", serde_json::json!({
            "scopes": ["read", "write", "admin"],
            "mandatory_scope": true,
            "token_expiration": 7200,
            "enable_authorization_code": true,
            "enable_client_credentials": true,
            "enable_implicit_grant": false,
            "enable_password_grant": false,
            "accept_http_if_already_terminated": true
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable rate limiting for a service
    pub async fn enable_rate_limiting(
        &self,
        service_id: &str,
        config: RateLimitConfig,
    ) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("rate-limiting", serde_json::json!({
            "second": config.requests_per_second,
            "minute": config.requests_per_minute,
            "hour": config.requests_per_hour,
            "day": config.requests_per_day,
            "policy": "local",
            "fault_tolerant": true,
            "hide_client_headers": false,
            "redis_ssl": false
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable request transformation
    pub async fn enable_request_transform(
        &self,
        service_id: &str,
        config: transform::TransformConfig,
    ) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("request-transformer", serde_json::json!({
            "add": {
                "headers": config.add_headers,
                "querystring": config.add_query_params,
                "body": config.add_body_params
            },
            "remove": {
                "headers": config.remove_headers,
                "querystring": config.remove_query_params
            },
            "rename": {
                "headers": config.rename_headers
            },
            "replace": {
                "headers": config.replace_headers
            }
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable CORS for a service
    pub async fn enable_cors(&self, service_id: &str, origins: Vec<String>) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("cors", serde_json::json!({
            "origins": origins,
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "headers": ["Accept", "Accept-Version", "Content-Length", "Content-Type", "Authorization", "X-API-Key"],
            "exposed_headers": ["X-Auth-Token", "X-Request-Id"],
            "credentials": true,
            "max_age": 3600,
            "preflight_continue": false
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable IP restriction for a service
    pub async fn enable_ip_restriction(
        &self,
        service_id: &str,
        allow: Vec<String>,
        deny: Vec<String>,
    ) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("ip-restriction", serde_json::json!({
            "allow": allow,
            "deny": deny
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable request size limiting
    pub async fn enable_request_size_limit(
        &self,
        service_id: &str,
        max_mb: u32,
    ) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("request-size-limiting", serde_json::json!({
            "allowed_payload_size": max_mb,
            "size_unit": "megabytes",
            "require_content_length": false
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable bot detection
    pub async fn enable_bot_detection(&self, service_id: &str) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("bot-detection", serde_json::json!({
            "allow": [],
            "deny": []
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable Prometheus metrics
    pub async fn enable_prometheus(&self) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("prometheus", serde_json::json!({
            "per_consumer": true,
            "status_code_metrics": true,
            "latency_metrics": true,
            "bandwidth_metrics": true,
            "upstream_health_metrics": true
        }));
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Enable logging
    pub async fn enable_logging(&self, service_id: &str, http_endpoint: &str) -> Result<Plugin, GatewayError> {
        let plugin = Plugin::new("http-log", serde_json::json!({
            "http_endpoint": http_endpoint,
            "method": "POST",
            "content_type": "application/json",
            "timeout": 10000,
            "keepalive": 60000,
            "retry_count": 3,
            "queue_size": 1000,
            "flush_timeout": 2
        })).for_service(service_id);
        
        self.kong.create_plugin(plugin).await
    }
    
    /// Generate API key for a consumer
    pub async fn create_api_key(&self, consumer_id: &str) -> Result<ApiKey, GatewayError> {
        self.kong.create_api_key(consumer_id).await
    }
    
    /// Generate JWT credentials for a consumer
    pub async fn create_jwt_credentials(&self, consumer_id: &str) -> Result<JwtCredential, GatewayError> {
        self.kong.create_jwt_credential(consumer_id).await
    }
    
    /// Get gateway status
    pub async fn status(&self) -> Result<GatewayStatus, GatewayError> {
        self.kong.get_status().await
    }
    
    /// List all services
    pub async fn list_services(&self) -> Result<Vec<Service>, GatewayError> {
        self.kong.list_services().await
    }
    
    /// List all routes
    pub async fn list_routes(&self) -> Result<Vec<Route>, GatewayError> {
        self.kong.list_routes().await
    }
    
    /// List all consumers
    pub async fn list_consumers(&self) -> Result<Vec<Consumer>, GatewayError> {
        self.kong.list_consumers().await
    }
    
    /// Delete a service
    pub async fn delete_service(&self, id: &str) -> Result<(), GatewayError> {
        self.kong.delete_service(id).await
    }
    
    /// Delete a route
    pub async fn delete_route(&self, id: &str) -> Result<(), GatewayError> {
        self.kong.delete_route(id).await
    }
}

// =============================================================================
// Additional Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub key: String,
    pub consumer_id: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtCredential {
    pub id: String,
    pub key: String,
    pub secret: String,
    pub consumer_id: String,
    pub algorithm: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayStatus {
    pub database: DatabaseStatus,
    pub server: ServerInfo,
    pub plugins: PluginsInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseStatus {
    pub reachable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    pub version: String,
    pub hostname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginsInfo {
    pub available_on_server: Vec<String>,
    pub enabled_in_cluster: Vec<String>,
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("Kong API error: {0}")]
    KongError(String),
    
    #[error("Authentication error: {0}")]
    AuthError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    
    #[error("Route not found: {0}")]
    RouteNotFound(String),
    
    #[error("Consumer not found: {0}")]
    ConsumerNotFound(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}
