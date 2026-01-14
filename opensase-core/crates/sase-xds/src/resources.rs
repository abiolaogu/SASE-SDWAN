//! xDS Resource Store
//!
//! Thread-safe storage for Envoy resources.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Serialize, Deserialize};

/// Listener resource
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Listener {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub filter_chains: Vec<FilterChain>,
}

impl Listener {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Filter chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterChain {
    pub name: String,
    pub filters: Vec<String>,
}

/// Cluster resource
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cluster {
    pub name: String,
    pub cluster_type: ClusterType,
    pub endpoints: Vec<Endpoint>,
    pub connect_timeout_ms: u64,
}

impl Cluster {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Cluster type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClusterType {
    Static,
    StrictDns,
    LogicalDns,
    Eds,
}

/// Endpoint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    pub weight: u32,
}

/// Route configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteConfiguration {
    pub name: String,
    pub virtual_hosts: Vec<VirtualHost>,
}

impl RouteConfiguration {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Virtual host
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtualHost {
    pub name: String,
    pub domains: Vec<String>,
    pub routes: Vec<Route>,
}

/// Route
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Route {
    pub match_prefix: String,
    pub cluster: String,
    pub timeout_ms: u64,
}

/// Resource store
pub struct ResourceStore {
    /// Listeners
    listeners: DashMap<String, Listener>,
    
    /// Clusters
    clusters: DashMap<String, Cluster>,
    
    /// Routes
    routes: DashMap<String, RouteConfiguration>,
    
    /// Version counter
    version: AtomicU64,
}

impl ResourceStore {
    /// Create new store
    pub fn new() -> Self {
        Self {
            listeners: DashMap::new(),
            clusters: DashMap::new(),
            routes: DashMap::new(),
            version: AtomicU64::new(1),
        }
    }
    
    /// Get current version
    pub fn get_version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }
    
    /// Increment version
    pub fn increment_version(&self) -> u64 {
        self.version.fetch_add(1, Ordering::Relaxed) + 1
    }
    
    // Listener operations
    
    pub fn add_listener(&self, listener: Listener) {
        self.listeners.insert(listener.name.clone(), listener);
        self.increment_version();
    }
    
    pub fn get_listener(&self, name: &str) -> Option<Listener> {
        self.listeners.get(name).map(|l| l.clone())
    }
    
    pub fn get_listeners(&self) -> Vec<Listener> {
        self.listeners.iter().map(|l| l.value().clone()).collect()
    }
    
    pub fn remove_listener(&self, name: &str) {
        self.listeners.remove(name);
        self.increment_version();
    }
    
    // Cluster operations
    
    pub fn add_cluster(&self, cluster: Cluster) {
        self.clusters.insert(cluster.name.clone(), cluster);
        self.increment_version();
    }
    
    pub fn get_cluster(&self, name: &str) -> Option<Cluster> {
        self.clusters.get(name).map(|c| c.clone())
    }
    
    pub fn get_clusters(&self) -> Vec<Cluster> {
        self.clusters.iter().map(|c| c.value().clone()).collect()
    }
    
    pub fn remove_cluster(&self, name: &str) {
        self.clusters.remove(name);
        self.increment_version();
    }
    
    // Route operations
    
    pub fn add_route(&self, route: RouteConfiguration) {
        self.routes.insert(route.name.clone(), route);
        self.increment_version();
    }
    
    pub fn get_route(&self, name: &str) -> Option<RouteConfiguration> {
        self.routes.get(name).map(|r| r.clone())
    }
    
    pub fn get_routes(&self) -> Vec<RouteConfiguration> {
        self.routes.iter().map(|r| r.value().clone()).collect()
    }
    
    pub fn remove_route(&self, name: &str) {
        self.routes.remove(name);
        self.increment_version();
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        Self::new()
    }
}
