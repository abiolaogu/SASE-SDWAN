//! High-performance LRU cache for policy decisions

use moka::sync::Cache;
use sase_common::PolicyKey;
use sase_common::policy::PolicyDecision;
use std::time::Duration;

/// Policy decision cache with LRU eviction
pub struct PolicyCache {
    cache: Cache<u64, (u64, PolicyDecision)>,  // (version, decision)
    capacity: u64,
}

impl PolicyCache {
    /// Create cache with capacity
    pub fn new(capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(60))
            .build();

        Self { cache, capacity }
    }

    /// Get cached decision if version matches
    #[inline(always)]
    pub fn get(&self, key: &PolicyKey, current_version: u64) -> Option<PolicyDecision> {
        let hash = key.hash_key();
        
        self.cache.get(&hash).and_then(|(version, decision)| {
            if version == current_version {
                Some(decision)
            } else {
                // Stale entry - version mismatch
                None
            }
        })
    }

    /// Insert decision into cache
    #[inline(always)]
    pub fn insert(&self, key: &PolicyKey, version: u64, decision: PolicyDecision) {
        let hash = key.hash_key();
        self.cache.insert(hash, (version, decision));
    }

    /// Get cache hit rate (estimated)
    pub fn hit_rate(&self) -> f64 {
        // moka stats requires extra config; return 0.0 for now
        0.0
    }

    /// Clear cache
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }

    /// Get current size
    pub fn len(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.cache.entry_count() == 0
    }
}

impl Default for PolicyCache {
    fn default() -> Self {
        Self::new(65536)  // 64K entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sase_common::policy::Action;

    #[test]
    fn test_cache_hit() {
        let cache = PolicyCache::new(100);
        let key = PolicyKey::from_ipv4(0xC0A80101, 0x08080808, 12345, 443, 6);
        let decision = PolicyDecision {
            action: Action::Allow,
            ..Default::default()
        };

        // Insert
        cache.insert(&key, 1, decision.clone());

        // Hit with same version
        let result = cache.get(&key, 1);
        assert!(result.is_some());
        assert_eq!(result.unwrap().action, Action::Allow);

        // Miss with different version
        let result = cache.get(&key, 2);
        assert!(result.is_none());
    }
}
