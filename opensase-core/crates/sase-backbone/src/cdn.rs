//! CDN Cache Layer

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;

/// CDN Cache Manager
pub struct CdnCache {
    /// Cache rules per tenant
    rules: Arc<RwLock<HashMap<Uuid, Vec<CacheRule>>>>,
    /// Cache entries
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cache stats
    stats: Arc<RwLock<CacheStats>>,
}

impl CdnCache {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// Add cache rule
    pub fn add_rule(&self, tenant_id: Uuid, rule: CacheRule) {
        self.rules.write().entry(tenant_id).or_default().push(rule);
    }

    /// Get cache rules for tenant
    pub fn get_rules(&self, tenant_id: Uuid) -> Vec<CacheRule> {
        self.rules.read().get(&tenant_id).cloned().unwrap_or_default()
    }

    /// Check if URL should be cached
    pub fn should_cache(&self, tenant_id: Uuid, url: &str, content_type: &str) -> Option<CacheRule> {
        let rules = self.rules.read();
        for rule in rules.get(&tenant_id).unwrap_or(&Vec::new()) {
            if rule.enabled && self.matches_rule(rule, url, content_type) {
                return Some(rule.clone());
            }
        }
        None
    }

    fn matches_rule(&self, rule: &CacheRule, url: &str, content_type: &str) -> bool {
        // Check path pattern
        if let Some(pattern) = &rule.path_pattern {
            if !url.contains(pattern) {
                return false;
            }
        }

        // Check content type
        if let Some(types) = &rule.content_types {
            if !types.iter().any(|t| content_type.starts_with(t)) {
                return false;
            }
        }

        true
    }

    /// Get from cache
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        let cache = self.cache.read();
        let entry = cache.get(key)?;
        
        // Check expiry
        if entry.expires_at < chrono::Utc::now() {
            return None;
        }

        // Update stats
        self.stats.write().hits += 1;
        Some(entry.clone())
    }

    /// Put in cache
    pub fn put(&self, key: &str, entry: CacheEntry) {
        self.cache.write().insert(key.to_string(), entry);
        self.stats.write().misses += 1;
    }

    /// Purge cache entry
    pub fn purge(&self, key: &str) -> bool {
        self.cache.write().remove(key).is_some()
    }

    /// Purge by prefix
    pub fn purge_prefix(&self, prefix: &str) -> usize {
        let mut cache = self.cache.write();
        let keys: Vec<_> = cache.keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        let count = keys.len();
        for key in keys {
            cache.remove(&key);
        }
        count
    }

    /// Get cache stats
    pub fn get_stats(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Calculate bandwidth savings
    pub fn bandwidth_savings(&self) -> BandwidthSavings {
        let stats = self.stats.read();
        let hit_rate = if stats.hits + stats.misses > 0 {
            stats.hits as f64 / (stats.hits + stats.misses) as f64
        } else {
            0.0
        };

        BandwidthSavings {
            hit_rate,
            bytes_saved: stats.bytes_served_from_cache,
            origin_bytes: stats.bytes_from_origin,
            cost_savings_estimate: (stats.bytes_served_from_cache as f64 / 1_000_000_000.0) * 0.08, // $0.08/GB estimate
        }
    }
}

impl Default for CdnCache {
    fn default() -> Self { Self::new() }
}

/// Cache rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub path_pattern: Option<String>,
    pub content_types: Option<Vec<String>>,
    pub ttl_seconds: u64,
    pub cache_control: CacheControl,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CacheControl {
    Cache,
    NoCache,
    NoStore,
    Private,
}

/// Cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Cache statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub bytes_served_from_cache: u64,
    pub bytes_from_origin: u64,
    pub entries_count: u64,
}

/// Bandwidth savings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthSavings {
    pub hit_rate: f64,
    pub bytes_saved: u64,
    pub origin_bytes: u64,
    pub cost_savings_estimate: f64,
}
