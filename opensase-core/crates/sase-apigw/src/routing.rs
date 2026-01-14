//! API Routing
//!
//! Advanced routing with versioning, A/B testing, and canary deployments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Route manager
pub struct RouteManager {
    routes: parking_lot::RwLock<Vec<RouteConfig>>,
    versions: parking_lot::RwLock<HashMap<String, ApiVersion>>,
}

/// Route configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteConfig {
    pub id: String,
    pub name: String,
    pub paths: Vec<String>,
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub headers: HashMap<String, String>,
    pub service_id: String,
    pub priority: i32,
    pub strip_path: bool,
    pub preserve_host: bool,
    pub enabled: bool,
}

/// API version
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiVersion {
    pub version: String,
    pub service_id: String,
    pub deprecated: bool,
    pub sunset_date: Option<String>,
    pub routes: Vec<String>,
}

/// Routing strategy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoutingStrategy {
    /// Route all traffic to primary
    Primary,
    /// Round-robin between targets
    RoundRobin,
    /// Weighted distribution
    Weighted(Vec<WeightedTarget>),
    /// Header-based routing
    HeaderBased(HeaderRoutingRule),
    /// Canary deployment
    Canary(CanaryConfig),
    /// A/B Testing
    AbTest(AbTestConfig),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedTarget {
    pub service_id: String,
    pub weight: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderRoutingRule {
    pub header_name: String,
    pub header_value: String,
    pub service_id: String,
    pub fallback_service_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanaryConfig {
    pub primary_service_id: String,
    pub canary_service_id: String,
    pub canary_percentage: u32,
    pub sticky_sessions: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbTestConfig {
    pub variants: Vec<AbVariant>,
    pub user_id_header: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbVariant {
    pub name: String,
    pub service_id: String,
    pub percentage: u32,
}

impl RouteManager {
    /// Create new route manager
    pub fn new() -> Self {
        Self {
            routes: parking_lot::RwLock::new(Vec::new()),
            versions: parking_lot::RwLock::new(HashMap::new()),
        }
    }
    
    /// Add a route
    pub fn add_route(&self, route: RouteConfig) {
        let mut routes = self.routes.write();
        routes.push(route);
        routes.sort_by_key(|r| std::cmp::Reverse(r.priority));
    }
    
    /// Remove a route
    pub fn remove_route(&self, id: &str) {
        self.routes.write().retain(|r| r.id != id);
    }
    
    /// Update a route
    pub fn update_route(&self, id: &str, route: RouteConfig) {
        let mut routes = self.routes.write();
        if let Some(existing) = routes.iter_mut().find(|r| r.id == id) {
            *existing = route;
        }
        routes.sort_by_key(|r| std::cmp::Reverse(r.priority));
    }
    
    /// Find matching route
    pub fn match_route(&self, request: &RouteRequest) -> Option<RouteConfig> {
        let routes = self.routes.read();
        
        for route in routes.iter() {
            if !route.enabled {
                continue;
            }
            
            // Match method
            if !route.methods.is_empty() && !route.methods.contains(&request.method) {
                continue;
            }
            
            // Match host
            if !route.hosts.is_empty() {
                let host_match = route.hosts.iter()
                    .any(|h| self.match_host(h, &request.host));
                if !host_match {
                    continue;
                }
            }
            
            // Match path
            if !route.paths.is_empty() {
                let path_match = route.paths.iter()
                    .any(|p| self.match_path(p, &request.path));
                if !path_match {
                    continue;
                }
            }
            
            // Match headers
            let headers_match = route.headers.iter()
                .all(|(k, v)| request.headers.get(k).map_or(false, |rv| rv == v));
            if !headers_match {
                continue;
            }
            
            return Some(route.clone());
        }
        
        None
    }
    
    /// Match host pattern
    fn match_host(&self, pattern: &str, host: &str) -> bool {
        if pattern.starts_with('*') {
            // Wildcard match
            let suffix = &pattern[1..];
            host.ends_with(suffix)
        } else {
            pattern == host
        }
    }
    
    /// Match path pattern
    fn match_path(&self, pattern: &str, path: &str) -> bool {
        if pattern.ends_with('*') {
            // Prefix match
            let prefix = &pattern[..pattern.len() - 1];
            path.starts_with(prefix)
        } else {
            pattern == path || path.starts_with(&format!("{}/", pattern))
        }
    }
    
    /// Register API version
    pub fn register_version(&self, api: &str, version: ApiVersion) {
        self.versions.write().insert(
            format!("{}:{}", api, version.version),
            version,
        );
    }
    
    /// Get API version
    pub fn get_version(&self, api: &str, version: &str) -> Option<ApiVersion> {
        self.versions.read().get(&format!("{}:{}", api, version)).cloned()
    }
    
    /// Get all versions for an API
    pub fn get_all_versions(&self, api: &str) -> Vec<ApiVersion> {
        self.versions.read()
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}:", api)))
            .map(|(_, v)| v.clone())
            .collect()
    }
    
    /// Select service based on routing strategy
    pub fn select_service(&self, strategy: &RoutingStrategy, request: &RouteRequest) -> String {
        match strategy {
            RoutingStrategy::Primary => {
                // Default behavior
                String::new()
            }
            RoutingStrategy::RoundRobin => {
                // Would need state for round-robin
                String::new()
            }
            RoutingStrategy::Weighted(targets) => {
                self.weighted_select(targets)
            }
            RoutingStrategy::HeaderBased(rule) => {
                if request.headers.get(&rule.header_name)
                    .map_or(false, |v| v == &rule.header_value)
                {
                    rule.service_id.clone()
                } else {
                    rule.fallback_service_id.clone()
                }
            }
            RoutingStrategy::Canary(config) => {
                self.canary_select(config, request)
            }
            RoutingStrategy::AbTest(config) => {
                self.ab_select(config, request)
            }
        }
    }
    
    /// Weighted random selection
    fn weighted_select(&self, targets: &[WeightedTarget]) -> String {
        let total_weight: u32 = targets.iter().map(|t| t.weight).sum();
        if total_weight == 0 {
            return String::new();
        }
        
        let random: u32 = rand::random::<u32>() % total_weight;
        let mut cumulative = 0;
        
        for target in targets {
            cumulative += target.weight;
            if random < cumulative {
                return target.service_id.clone();
            }
        }
        
        targets.last().map(|t| t.service_id.clone()).unwrap_or_default()
    }
    
    /// Canary deployment selection
    fn canary_select(&self, config: &CanaryConfig, request: &RouteRequest) -> String {
        // Use hash for sticky sessions
        if config.sticky_sessions {
            let user_hash = Self::hash_user(&request.client_ip);
            if user_hash % 100 < config.canary_percentage {
                return config.canary_service_id.clone();
            } else {
                return config.primary_service_id.clone();
            }
        }
        
        // Random selection
        let random: u32 = rand::random::<u32>() % 100;
        if random < config.canary_percentage {
            config.canary_service_id.clone()
        } else {
            config.primary_service_id.clone()
        }
    }
    
    /// A/B test selection
    fn ab_select(&self, config: &AbTestConfig, request: &RouteRequest) -> String {
        let user_id = request.headers.get(&config.user_id_header)
            .cloned()
            .unwrap_or_else(|| request.client_ip.clone());
        
        let hash = Self::hash_user(&user_id) % 100;
        let mut cumulative = 0;
        
        for variant in &config.variants {
            cumulative += variant.percentage;
            if hash < cumulative {
                return variant.service_id.clone();
            }
        }
        
        config.variants.last().map(|v| v.service_id.clone()).unwrap_or_default()
    }
    
    /// Simple string hash
    fn hash_user(user: &str) -> u32 {
        let mut hash = 0u32;
        for byte in user.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }
        hash
    }
}

impl Default for RouteManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Route request
#[derive(Clone, Debug)]
pub struct RouteRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub client_ip: String,
}

impl RouteRequest {
    pub fn new(method: &str, host: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            client_ip: String::new(),
        }
    }
    
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }
    
    pub fn with_client_ip(mut self, ip: &str) -> Self {
        self.client_ip = ip.to_string();
        self
    }
}
