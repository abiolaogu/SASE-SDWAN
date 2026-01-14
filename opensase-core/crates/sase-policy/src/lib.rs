//! Ultra-Fast Policy Engine
//!
//! Target: <1μs policy lookup, 10M+ decisions/second
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Policy Lookup                            │
//! │                                                             │
//! │  ┌─────────────┐   Miss   ┌─────────────┐   Miss   ┌──────┐│
//! │  │ Bloom Filter│────────►│  LRU Cache  │────────►│Policy││
//! │  │   (32KB)    │         │  (64K entries)│        │ Trie ││
//! │  └─────────────┘         └─────────────┘         └──────┘│
//! │        │ Hit (definite no)      │ Hit (<100ns)           │
//! │        ▼                        ▼                        │
//! │    [ALLOW]                 [Decision]              [Lookup]│
//! └─────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]

pub mod engine;
pub mod store;
pub mod cache;
pub mod bloom;

pub use engine::{PolicyEngine, EngineStats};
pub use store::PolicyStore;

use sase_common::PolicyKey;
use sase_common::policy::{PolicyDecision, Action};

/// Policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Rule ID
    pub id: u32,
    /// Source CIDR (network, prefix_len)
    pub src_cidr: Option<(u128, u8)>,
    /// Destination CIDR
    pub dst_cidr: Option<(u128, u8)>,
    /// Source port range (start, end)
    pub src_port_range: Option<(u16, u16)>,
    /// Destination port range
    pub dst_port_range: Option<(u16, u16)>,
    /// Protocol (None = any)
    pub protocol: Option<u8>,
    /// Source segment
    pub src_segment: Option<u8>,
    /// Destination segment
    pub dst_segment: Option<u8>,
    /// User groups required
    pub user_groups: Vec<u8>,
    /// Decision to apply
    pub decision: PolicyDecision,
}

impl PolicyRule {
    /// Create allow rule
    pub fn allow(id: u32) -> Self {
        Self {
            id,
            src_cidr: None,
            dst_cidr: None,
            src_port_range: None,
            dst_port_range: None,
            protocol: None,
            src_segment: None,
            dst_segment: None,
            user_groups: vec![],
            decision: PolicyDecision {
                action: Action::Allow,
                ..Default::default()
            },
        }
    }

    /// Create deny rule
    pub fn deny(id: u32) -> Self {
        Self {
            id,
            decision: PolicyDecision {
                action: Action::Deny,
                rule_id: id,
                ..Default::default()
            },
            ..Self::allow(id)
        }
    }

    /// Match against key
    #[inline]
    pub fn matches(&self, key: &PolicyKey) -> bool {
        // Check source CIDR
        if let Some((network, prefix_len)) = self.src_cidr {
            if !Self::cidr_matches(key.src_ip, network, prefix_len) {
                return false;
            }
        }

        // Check destination CIDR
        if let Some((network, prefix_len)) = self.dst_cidr {
            if !Self::cidr_matches(key.dst_ip, network, prefix_len) {
                return false;
            }
        }

        // Check source port
        if let Some((start, end)) = self.src_port_range {
            if key.src_port < start || key.src_port > end {
                return false;
            }
        }

        // Check destination port
        if let Some((start, end)) = self.dst_port_range {
            if key.dst_port < start || key.dst_port > end {
                return false;
            }
        }

        // Check protocol
        if let Some(proto) = self.protocol {
            if key.protocol != proto {
                return false;
            }
        }

        // Check segments
        if let Some(seg) = self.src_segment {
            if key.src_segment != seg {
                return false;
            }
        }

        if let Some(seg) = self.dst_segment {
            if key.dst_segment != seg {
                return false;
            }
        }

        // Check user groups
        if !self.user_groups.is_empty() && !self.user_groups.contains(&key.user_group) {
            return false;
        }

        true
    }

    #[inline]
    fn cidr_matches(ip: u128, network: u128, prefix_len: u8) -> bool {
        if prefix_len == 0 {
            return true;
        }
        if prefix_len >= 128 {
            return ip == network;
        }
        let mask = !0u128 << (128 - prefix_len);
        (ip & mask) == (network & mask)
    }
}

/// Statistics for policy engine
#[derive(Debug, Default, Clone)]
pub struct PolicyStats {
    /// Total lookups
    pub lookups: u64,
    /// Bloom filter hits (fast path)
    pub bloom_hits: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Full lookups
    pub full_lookups: u64,
    /// Average lookup time in nanoseconds
    pub avg_lookup_ns: u64,
    /// P99 lookup time in nanoseconds
    pub p99_lookup_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matching() {
        let rule = PolicyRule {
            id: 1,
            src_cidr: Some((0xC0A80100, 24)),  // 192.168.1.0/24
            dst_cidr: None,
            src_port_range: None,
            dst_port_range: Some((443, 443)),
            protocol: Some(6),  // TCP
            src_segment: None,
            dst_segment: None,
            user_groups: vec![],
            decision: PolicyDecision::default(),
        };

        // Matching key
        let key = PolicyKey::from_ipv4(
            0xC0A80105,  // 192.168.1.5
            0x08080808,  // 8.8.8.8
            12345,
            443,
            6,
        );
        assert!(rule.matches(&key));

        // Non-matching key (wrong port)
        let key2 = PolicyKey::from_ipv4(
            0xC0A80105,
            0x08080808,
            12345,
            80,  // Wrong port
            6,
        );
        assert!(!rule.matches(&key2));
    }
}
