//! Request/Response Transformation
//!
//! Transform requests and responses as they pass through the gateway.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Transformation configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransformConfig {
    // Headers
    pub add_headers: HashMap<String, String>,
    pub remove_headers: Vec<String>,
    pub rename_headers: HashMap<String, String>,
    pub replace_headers: HashMap<String, String>,
    
    // Query parameters
    pub add_query_params: HashMap<String, String>,
    pub remove_query_params: Vec<String>,
    
    // Body
    pub add_body_params: HashMap<String, String>,
    pub remove_body_params: Vec<String>,
    
    // Path
    pub path_prefix: Option<String>,
    pub path_strip_prefix: Option<String>,
    pub path_replace: Option<(String, String)>,
}

impl TransformConfig {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.add_headers.insert(name.to_string(), value.to_string());
        self
    }
    
    pub fn remove_header(mut self, name: &str) -> Self {
        self.remove_headers.push(name.to_string());
        self
    }
    
    pub fn rename_header(mut self, from: &str, to: &str) -> Self {
        self.rename_headers.insert(from.to_string(), to.to_string());
        self
    }
    
    pub fn add_query_param(mut self, name: &str, value: &str) -> Self {
        self.add_query_params.insert(name.to_string(), value.to_string());
        self
    }
    
    pub fn remove_query_param(mut self, name: &str) -> Self {
        self.remove_query_params.push(name.to_string());
        self
    }
    
    pub fn with_path_prefix(mut self, prefix: &str) -> Self {
        self.path_prefix = Some(prefix.to_string());
        self
    }
    
    pub fn strip_path_prefix(mut self, prefix: &str) -> Self {
        self.path_strip_prefix = Some(prefix.to_string());
        self
    }
}

/// Request transformer
pub struct RequestTransformer {
    config: TransformConfig,
}

impl RequestTransformer {
    pub fn new(config: TransformConfig) -> Self {
        Self { config }
    }
    
    /// Transform headers
    pub fn transform_headers(&self, headers: &mut HashMap<String, String>) {
        // Remove headers
        for header in &self.config.remove_headers {
            headers.remove(header);
        }
        
        // Rename headers
        for (from, to) in &self.config.rename_headers {
            if let Some(value) = headers.remove(from) {
                headers.insert(to.clone(), value);
            }
        }
        
        // Replace headers
        for (name, value) in &self.config.replace_headers {
            if headers.contains_key(name) {
                headers.insert(name.clone(), value.clone());
            }
        }
        
        // Add headers
        for (name, value) in &self.config.add_headers {
            headers.insert(name.clone(), value.clone());
        }
    }
    
    /// Transform query string
    pub fn transform_query(&self, query: &mut HashMap<String, String>) {
        // Remove params
        for param in &self.config.remove_query_params {
            query.remove(param);
        }
        
        // Add params
        for (name, value) in &self.config.add_query_params {
            query.insert(name.clone(), value.clone());
        }
    }
    
    /// Transform path
    pub fn transform_path(&self, path: &str) -> String {
        let mut result = path.to_string();
        
        // Strip prefix
        if let Some(prefix) = &self.config.path_strip_prefix {
            if result.starts_with(prefix) {
                result = result[prefix.len()..].to_string();
            }
        }
        
        // Add prefix
        if let Some(prefix) = &self.config.path_prefix {
            result = format!("{}{}", prefix, result);
        }
        
        // Replace
        if let Some((from, to)) = &self.config.path_replace {
            result = result.replace(from, to);
        }
        
        result
    }
    
    /// Transform JSON body
    pub fn transform_json_body(&self, body: &mut serde_json::Value) {
        if let Some(obj) = body.as_object_mut() {
            // Remove params
            for param in &self.config.remove_body_params {
                obj.remove(param);
            }
            
            // Add params
            for (name, value) in &self.config.add_body_params {
                obj.insert(name.clone(), serde_json::Value::String(value.clone()));
            }
        }
    }
}

/// Response transformer
pub struct ResponseTransformer {
    config: ResponseTransformConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResponseTransformConfig {
    pub add_headers: HashMap<String, String>,
    pub remove_headers: Vec<String>,
    pub json_mask_fields: Vec<String>,
    pub json_remove_fields: Vec<String>,
}

impl ResponseTransformer {
    pub fn new(config: ResponseTransformConfig) -> Self {
        Self { config }
    }
    
    /// Transform response headers
    pub fn transform_headers(&self, headers: &mut HashMap<String, String>) {
        // Remove headers
        for header in &self.config.remove_headers {
            headers.remove(header);
        }
        
        // Add headers
        for (name, value) in &self.config.add_headers {
            headers.insert(name.clone(), value.clone());
        }
    }
    
    /// Transform JSON response body
    pub fn transform_json_body(&self, body: &mut serde_json::Value) {
        self.mask_fields(body);
        self.remove_fields(body);
    }
    
    fn mask_fields(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(obj) => {
                for (key, val) in obj.iter_mut() {
                    if self.config.json_mask_fields.contains(key) {
                        if let serde_json::Value::String(s) = val {
                            *val = serde_json::Value::String("***MASKED***".to_string());
                        }
                    } else {
                        self.mask_fields(val);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.mask_fields(item);
                }
            }
            _ => {}
        }
    }
    
    fn remove_fields(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(obj) => {
                for field in &self.config.json_remove_fields {
                    obj.remove(field);
                }
                for (_, val) in obj.iter_mut() {
                    self.remove_fields(val);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.remove_fields(item);
                }
            }
            _ => {}
        }
    }
}

/// Template-based transformation
pub struct TemplateTransformer {
    templates: HashMap<String, String>,
}

impl TemplateTransformer {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }
    
    /// Register a template
    pub fn register(&mut self, name: &str, template: &str) {
        self.templates.insert(name.to_string(), template.to_string());
    }
    
    /// Apply template with variables
    pub fn apply(&self, name: &str, vars: &HashMap<String, String>) -> Option<String> {
        let template = self.templates.get(name)?;
        let mut result = template.clone();
        
        for (key, value) in vars {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }
        
        Some(result)
    }
}

impl Default for TemplateTransformer {
    fn default() -> Self {
        Self::new()
    }
}
