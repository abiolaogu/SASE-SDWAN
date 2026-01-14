//! Kong Admin API Client
//!
//! HTTP client for Kong Gateway Admin API.

use crate::{
    ApiKey, Consumer, GatewayError, GatewayStatus, JwtCredential, Plugin, Route, Service,
};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Kong Admin API client
pub struct KongClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KongList<T> {
    data: Vec<T>,
    next: Option<String>,
}

impl KongClient {
    /// Create new Kong client
    pub fn new(base_url: &str, api_key: Option<String>) -> Result<Self, GatewayError> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        
        if let Some(ref key) = api_key {
            headers.insert(
                "Kong-Admin-Token",
                HeaderValue::from_str(key).map_err(|e| GatewayError::ConfigError(e.to_string()))?,
            );
        }
        
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
        })
    }
    
    /// Get Kong status
    pub async fn get_status(&self) -> Result<GatewayStatus, GatewayError> {
        let url = format!("{}/status", self.base_url);
        self.get(&url).await
    }
    
    // =========================================================================
    // Services
    // =========================================================================
    
    /// Create a service
    pub async fn create_service(&self, service: Service) -> Result<Service, GatewayError> {
        let url = format!("{}/services", self.base_url);
        self.post(&url, &service).await
    }
    
    /// Get a service by ID or name
    pub async fn get_service(&self, id_or_name: &str) -> Result<Service, GatewayError> {
        let url = format!("{}/services/{}", self.base_url, id_or_name);
        self.get(&url).await
    }
    
    /// Update a service
    pub async fn update_service(&self, id: &str, service: Service) -> Result<Service, GatewayError> {
        let url = format!("{}/services/{}", self.base_url, id);
        self.patch(&url, &service).await
    }
    
    /// Delete a service
    pub async fn delete_service(&self, id: &str) -> Result<(), GatewayError> {
        let url = format!("{}/services/{}", self.base_url, id);
        self.delete(&url).await
    }
    
    /// List all services
    pub async fn list_services(&self) -> Result<Vec<Service>, GatewayError> {
        let url = format!("{}/services", self.base_url);
        let result: KongList<Service> = self.get(&url).await?;
        Ok(result.data)
    }
    
    // =========================================================================
    // Routes
    // =========================================================================
    
    /// Create a route
    pub async fn create_route(&self, route: Route) -> Result<Route, GatewayError> {
        let url = format!("{}/routes", self.base_url);
        self.post(&url, &route).await
    }
    
    /// Get a route by ID or name
    pub async fn get_route(&self, id_or_name: &str) -> Result<Route, GatewayError> {
        let url = format!("{}/routes/{}", self.base_url, id_or_name);
        self.get(&url).await
    }
    
    /// Update a route
    pub async fn update_route(&self, id: &str, route: Route) -> Result<Route, GatewayError> {
        let url = format!("{}/routes/{}", self.base_url, id);
        self.patch(&url, &route).await
    }
    
    /// Delete a route
    pub async fn delete_route(&self, id: &str) -> Result<(), GatewayError> {
        let url = format!("{}/routes/{}", self.base_url, id);
        self.delete(&url).await
    }
    
    /// List all routes
    pub async fn list_routes(&self) -> Result<Vec<Route>, GatewayError> {
        let url = format!("{}/routes", self.base_url);
        let result: KongList<Route> = self.get(&url).await?;
        Ok(result.data)
    }
    
    /// List routes for a service
    pub async fn list_service_routes(&self, service_id: &str) -> Result<Vec<Route>, GatewayError> {
        let url = format!("{}/services/{}/routes", self.base_url, service_id);
        let result: KongList<Route> = self.get(&url).await?;
        Ok(result.data)
    }
    
    // =========================================================================
    // Consumers
    // =========================================================================
    
    /// Create a consumer
    pub async fn create_consumer(&self, consumer: Consumer) -> Result<Consumer, GatewayError> {
        let url = format!("{}/consumers", self.base_url);
        self.post(&url, &consumer).await
    }
    
    /// Get a consumer by ID or username
    pub async fn get_consumer(&self, id_or_username: &str) -> Result<Consumer, GatewayError> {
        let url = format!("{}/consumers/{}", self.base_url, id_or_username);
        self.get(&url).await
    }
    
    /// Update a consumer
    pub async fn update_consumer(&self, id: &str, consumer: Consumer) -> Result<Consumer, GatewayError> {
        let url = format!("{}/consumers/{}", self.base_url, id);
        self.patch(&url, &consumer).await
    }
    
    /// Delete a consumer
    pub async fn delete_consumer(&self, id: &str) -> Result<(), GatewayError> {
        let url = format!("{}/consumers/{}", self.base_url, id);
        self.delete(&url).await
    }
    
    /// List all consumers
    pub async fn list_consumers(&self) -> Result<Vec<Consumer>, GatewayError> {
        let url = format!("{}/consumers", self.base_url);
        let result: KongList<Consumer> = self.get(&url).await?;
        Ok(result.data)
    }
    
    // =========================================================================
    // Plugins
    // =========================================================================
    
    /// Create a plugin
    pub async fn create_plugin(&self, plugin: Plugin) -> Result<Plugin, GatewayError> {
        let url = format!("{}/plugins", self.base_url);
        self.post(&url, &plugin).await
    }
    
    /// Get a plugin by ID
    pub async fn get_plugin(&self, id: &str) -> Result<Plugin, GatewayError> {
        let url = format!("{}/plugins/{}", self.base_url, id);
        self.get(&url).await
    }
    
    /// Update a plugin
    pub async fn update_plugin(&self, id: &str, plugin: Plugin) -> Result<Plugin, GatewayError> {
        let url = format!("{}/plugins/{}", self.base_url, id);
        self.patch(&url, &plugin).await
    }
    
    /// Delete a plugin
    pub async fn delete_plugin(&self, id: &str) -> Result<(), GatewayError> {
        let url = format!("{}/plugins/{}", self.base_url, id);
        self.delete(&url).await
    }
    
    /// List all plugins
    pub async fn list_plugins(&self) -> Result<Vec<Plugin>, GatewayError> {
        let url = format!("{}/plugins", self.base_url);
        let result: KongList<Plugin> = self.get(&url).await?;
        Ok(result.data)
    }
    
    /// List plugins for a service
    pub async fn list_service_plugins(&self, service_id: &str) -> Result<Vec<Plugin>, GatewayError> {
        let url = format!("{}/services/{}/plugins", self.base_url, service_id);
        let result: KongList<Plugin> = self.get(&url).await?;
        Ok(result.data)
    }
    
    // =========================================================================
    // Credentials
    // =========================================================================
    
    /// Create API key for consumer
    pub async fn create_api_key(&self, consumer_id: &str) -> Result<ApiKey, GatewayError> {
        let url = format!("{}/consumers/{}/key-auth", self.base_url, consumer_id);
        
        #[derive(Serialize)]
        struct EmptyBody {}
        
        self.post(&url, &EmptyBody {}).await
    }
    
    /// Create API key with specific value
    pub async fn create_api_key_with_value(&self, consumer_id: &str, key: &str) -> Result<ApiKey, GatewayError> {
        let url = format!("{}/consumers/{}/key-auth", self.base_url, consumer_id);
        
        #[derive(Serialize)]
        struct KeyBody {
            key: String,
        }
        
        self.post(&url, &KeyBody { key: key.to_string() }).await
    }
    
    /// List API keys for consumer
    pub async fn list_api_keys(&self, consumer_id: &str) -> Result<Vec<ApiKey>, GatewayError> {
        let url = format!("{}/consumers/{}/key-auth", self.base_url, consumer_id);
        let result: KongList<ApiKey> = self.get(&url).await?;
        Ok(result.data)
    }
    
    /// Delete API key
    pub async fn delete_api_key(&self, consumer_id: &str, key_id: &str) -> Result<(), GatewayError> {
        let url = format!("{}/consumers/{}/key-auth/{}", self.base_url, consumer_id, key_id);
        self.delete(&url).await
    }
    
    /// Create JWT credential for consumer
    pub async fn create_jwt_credential(&self, consumer_id: &str) -> Result<JwtCredential, GatewayError> {
        let url = format!("{}/consumers/{}/jwt", self.base_url, consumer_id);
        
        #[derive(Serialize)]
        struct JwtBody {
            algorithm: String,
        }
        
        self.post(&url, &JwtBody { algorithm: "HS256".to_string() }).await
    }
    
    /// List JWT credentials for consumer
    pub async fn list_jwt_credentials(&self, consumer_id: &str) -> Result<Vec<JwtCredential>, GatewayError> {
        let url = format!("{}/consumers/{}/jwt", self.base_url, consumer_id);
        let result: KongList<JwtCredential> = self.get(&url).await?;
        Ok(result.data)
    }
    
    // =========================================================================
    // Upstreams and Targets (Load Balancing)
    // =========================================================================
    
    /// Create an upstream
    pub async fn create_upstream(&self, upstream: Upstream) -> Result<Upstream, GatewayError> {
        let url = format!("{}/upstreams", self.base_url);
        self.post(&url, &upstream).await
    }
    
    /// Add a target to an upstream
    pub async fn add_target(&self, upstream_id: &str, target: Target) -> Result<Target, GatewayError> {
        let url = format!("{}/upstreams/{}/targets", self.base_url, upstream_id);
        self.post(&url, &target).await
    }
    
    /// List targets for an upstream
    pub async fn list_targets(&self, upstream_id: &str) -> Result<Vec<Target>, GatewayError> {
        let url = format!("{}/upstreams/{}/targets", self.base_url, upstream_id);
        let result: KongList<Target> = self.get(&url).await?;
        Ok(result.data)
    }
    
    // =========================================================================
    // HTTP Helpers
    // =========================================================================
    
    async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T, GatewayError> {
        let response = self.client.get(url).send().await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(GatewayError::KongError(format!("{}: {}", status, text)));
        }
        
        response.json().await.map_err(|e| GatewayError::KongError(e.to_string()))
    }
    
    async fn post<T: Serialize, R: DeserializeOwned>(&self, url: &str, body: &T) -> Result<R, GatewayError> {
        let response = self.client.post(url).json(body).send().await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(GatewayError::KongError(format!("{}: {}", status, text)));
        }
        
        response.json().await.map_err(|e| GatewayError::KongError(e.to_string()))
    }
    
    async fn patch<T: Serialize, R: DeserializeOwned>(&self, url: &str, body: &T) -> Result<R, GatewayError> {
        let response = self.client.patch(url).json(body).send().await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(GatewayError::KongError(format!("{}: {}", status, text)));
        }
        
        response.json().await.map_err(|e| GatewayError::KongError(e.to_string()))
    }
    
    async fn delete(&self, url: &str) -> Result<(), GatewayError> {
        let response = self.client.delete(url).send().await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(GatewayError::KongError(format!("{}: {}", status, text)));
        }
        
        Ok(())
    }
}

// =============================================================================
// Load Balancing Types
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Upstream {
    pub id: Option<String>,
    pub name: String,
    pub algorithm: String,
    pub slots: Option<u32>,
    pub healthchecks: Option<HealthChecks>,
    pub tags: Option<Vec<String>>,
}

impl Upstream {
    pub fn new(name: &str) -> Self {
        Self {
            id: None,
            name: name.to_string(),
            algorithm: "round-robin".to_string(),
            slots: Some(10000),
            healthchecks: None,
            tags: None,
        }
    }
    
    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = algorithm.to_string();
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthChecks {
    pub active: Option<ActiveHealthCheck>,
    pub passive: Option<PassiveHealthCheck>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveHealthCheck {
    pub healthy: HealthyConfig,
    pub unhealthy: UnhealthyConfig,
    pub http_path: String,
    pub timeout: u32,
    pub concurrency: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassiveHealthCheck {
    pub healthy: HealthyConfig,
    pub unhealthy: UnhealthyConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthyConfig {
    pub interval: u32,
    pub successes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnhealthyConfig {
    pub interval: u32,
    pub http_failures: u32,
    pub tcp_failures: u32,
    pub timeouts: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub id: Option<String>,
    pub target: String,
    pub weight: u32,
    pub tags: Option<Vec<String>>,
}

impl Target {
    pub fn new(target: &str, weight: u32) -> Self {
        Self {
            id: None,
            target: target.to_string(),
            weight,
            tags: None,
        }
    }
}
