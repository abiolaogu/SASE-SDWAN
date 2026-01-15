//! HTTP client infrastructure
use std::sync::Arc;
use std::time::Duration;
use reqwest::{header, Method};
use serde::{de::DeserializeOwned, Serialize};
use crate::error::{Error, Result};
use crate::DEFAULT_BASE_URL;

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub base_url: String,
    pub api_key: String,
    pub timeout: Duration,
    pub max_retries: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self { base_url: DEFAULT_BASE_URL.to_string(), api_key: String::new(), timeout: Duration::from_secs(30), max_retries: 3 }
    }
}

/// OpenSASE API Client
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    config: ClientConfig,
    http: reqwest::Client,
}

impl Client {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_config(ClientConfig { api_key: api_key.into(), ..Default::default() })
    }
    
    pub fn with_config(config: ClientConfig) -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&format!("Bearer {}", config.api_key)).unwrap());
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::USER_AGENT, header::HeaderValue::from_static("opensase-sdk/1.0.0"));
        
        let http = reqwest::Client::builder().default_headers(headers).timeout(config.timeout).build().unwrap();
        Self { inner: Arc::new(ClientInner { config, http }) }
    }
    
    pub fn identity(&self) -> crate::services::IdentityService { crate::services::IdentityService::new(self.clone()) }
    pub fn crm(&self) -> crate::services::CrmService { crate::services::CrmService::new(self.clone()) }
    pub fn payments(&self) -> crate::services::PaymentsService { crate::services::PaymentsService::new(self.clone()) }
    
    pub(crate) async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> { self.request(Method::GET, path, None::<()>).await }
    pub(crate) async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: B) -> Result<T> { self.request(Method::POST, path, Some(body)).await }
    pub(crate) async fn patch<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: B) -> Result<T> { self.request(Method::PATCH, path, Some(body)).await }
    pub(crate) async fn delete(&self, path: &str) -> Result<()> { self.request::<(), ()>(Method::DELETE, path, None).await.map(|_| ()) }
    
    async fn request<T: DeserializeOwned, B: Serialize>(&self, method: Method, path: &str, body: Option<B>) -> Result<T> {
        let url = format!("{}{}", self.inner.config.base_url, path);
        let mut req = self.inner.http.request(method, &url);
        if let Some(b) = body { req = req.json(&b); }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(Error::Api { code: "error".into(), message: format!("HTTP {}", status), status_code: status, request_id: None, details: vec![] });
        }
        Ok(resp.json().await?)
    }
}
