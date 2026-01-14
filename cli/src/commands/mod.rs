//! CLI Commands

pub mod sites;
pub mod users;
pub mod policies;
pub mod alerts;
pub mod analytics;
pub mod config;

use serde::de::DeserializeOwned;

/// API client
pub struct ApiClient {
    pub base_url: String,
    pub api_key: Option<String>,
    pub tenant_id: Option<String>,
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new(base_url: &str, api_key: Option<&str>, tenant_id: Option<&str>) -> Self {
        Self {
            base_url: base_url.to_string(),
            api_key: api_key.map(String::from),
            tenant_id: tenant_id.map(String::from),
            client: reqwest::Client::new(),
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, self.tenant_path(path));
        let mut req = self.client.get(&url);
        
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        
        if let Some(data) = json.get("data") {
            serde_json::from_value(data.clone()).map_err(|e| e.to_string())
        } else {
            Err("No data in response".into())
        }
    }

    pub async fn post<T: DeserializeOwned, B: serde::Serialize>(&self, path: &str, body: &B) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, self.tenant_path(path));
        let mut req = self.client.post(&url).json(body);
        
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        
        if let Some(data) = json.get("data") {
            serde_json::from_value(data.clone()).map_err(|e| e.to_string())
        } else {
            Err("No data in response".into())
        }
    }

    fn tenant_path(&self, path: &str) -> String {
        if let Some(tenant) = &self.tenant_id {
            format!("/tenants/{}{}", tenant, path)
        } else {
            path.to_string()
        }
    }
}
