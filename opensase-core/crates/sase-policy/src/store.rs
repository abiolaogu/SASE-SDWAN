//! Lock-free policy store with hot-swapping

use arc_swap::ArcSwap;
use std::sync::Arc;
use sase_common::PolicyKey;
use sase_common::policy::PolicyDecision;
use crate::PolicyRule;

/// Lock-free policy store with atomic updates
pub struct PolicyStore {
    /// Current rule set (atomically swappable)
    rules: ArcSwap<Vec<PolicyRule>>,
    /// Version for cache invalidation
    version: std::sync::atomic::AtomicU64,
}

impl PolicyStore {
    /// Create empty store
    pub fn new() -> Self {
        Self {
            rules: ArcSwap::from_pointee(Vec::new()),
            version: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create with initial rules
    pub fn with_rules(rules: Vec<PolicyRule>) -> Self {
        Self {
            rules: ArcSwap::from_pointee(rules),
            version: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Get current version
    #[inline(always)]
    pub fn version(&self) -> u64 {
        self.version.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Lookup policy (linear scan - use cache for fast path)
    #[inline]
    pub fn lookup(&self, key: &PolicyKey) -> Option<PolicyDecision> {
        let rules = self.rules.load();
        
        // Find first matching rule
        for rule in rules.iter() {
            if rule.matches(key) {
                return Some(rule.decision.clone());
            }
        }
        
        None
    }

    /// Get number of rules
    pub fn len(&self) -> usize {
        self.rules.load().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.load().is_empty()
    }

    /// Atomically update rules (lock-free)
    pub fn update(&self, new_rules: Vec<PolicyRule>) {
        self.rules.store(Arc::new(new_rules));
        self.version.fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// Get current rules (for inspection)
    pub fn get_rules(&self) -> Arc<Vec<PolicyRule>> {
        self.rules.load_full()
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sase_common::policy::Action;

    #[test]
    fn test_store_update() {
        let store = PolicyStore::new();
        assert_eq!(store.version(), 0);
        assert!(store.is_empty());

        // Add rules
        store.update(vec![
            PolicyRule::allow(1),
            PolicyRule::deny(2),
        ]);

        assert_eq!(store.version(), 1);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_store_lookup() {
        let mut rule = PolicyRule::deny(1);
        rule.dst_port_range = Some((443, 443));

        let store = PolicyStore::with_rules(vec![rule]);

        // Matching key
        let key = PolicyKey::from_ipv4(0, 0, 0, 443, 6);
        let decision = store.lookup(&key).unwrap();
        assert_eq!(decision.action, Action::Deny);

        // Non-matching key
        let key2 = PolicyKey::from_ipv4(0, 0, 0, 80, 6);
        assert!(store.lookup(&key2).is_none());
    }
}
