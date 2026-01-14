//! Policy types for ultra-fast policy lookup
//!
//! Designed for <1μs lookup with:
//! - Perfect hashing for O(1) access
//! - Cache-line aligned structures
//! - Zero-copy serialization

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Action {
    /// Allow traffic
    Allow = 0,
    /// Deny traffic
    Deny = 1,
    /// Inspect traffic (DLP, IPS)
    Inspect = 2,
    /// Log only
    Log = 3,
    /// Rate limit
    RateLimit = 4,
    /// Redirect to proxy
    Redirect = 5,
}

impl Default for Action {
    fn default() -> Self {
        Self::Allow
    }
}

/// Inspection level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum InspectionLevel {
    /// No inspection
    None = 0,
    /// Metadata only (headers)
    Metadata = 1,
    /// Full content inspection
    Full = 2,
    /// Deep packet inspection with ML
    DeepML = 3,
}

impl Default for InspectionLevel {
    fn default() -> Self {
        Self::Metadata
    }
}

/// Network segment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Segment {
    /// Segment ID (0-4095)
    pub id: u16,
    /// VLAN tag
    pub vlan: u16,
    /// VRF ID
    pub vrf: u16,
    /// Reserved for alignment
    _reserved: u16,
}

impl Segment {
    /// Create new segment
    pub const fn new(id: u16, vlan: u16, vrf: u16) -> Self {
        Self {
            id,
            vlan,
            vrf,
            _reserved: 0,
        }
    }
}

/// Policy rule key for fast lookup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C, align(64))]
pub struct PolicyKey {
    /// Source IP (v4 in low 4 bytes, v6 full)
    pub src_ip: u128,
    /// Destination IP
    pub dst_ip: u128,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17)
    pub protocol: u8,
    /// Source segment
    pub src_segment: u8,
    /// Destination segment
    pub dst_segment: u8,
    /// User group ID
    pub user_group: u8,
}

impl PolicyKey {
    /// Create key from IPv4 addresses
    #[inline(always)]
    pub fn from_ipv4(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip: src_ip as u128,
            dst_ip: dst_ip as u128,
            src_port,
            dst_port,
            protocol,
            src_segment: 0,
            dst_segment: 0,
            user_group: 0,
        }
    }

    /// Hash for policy lookup (FNV-1a optimized)
    #[inline(always)]
    pub fn hash_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

/// Policy decision (result of lookup)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(32))]
pub struct PolicyDecision {
    /// Action to take
    pub action: Action,
    /// Inspection level
    pub inspection: InspectionLevel,
    /// Rate limit (packets per second, 0 = unlimited)
    pub rate_limit_pps: u32,
    /// Priority (lower = higher priority)
    pub priority: u16,
    /// Rule ID for logging
    pub rule_id: u32,
    /// Flags
    pub flags: u16,
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self {
            action: Action::Allow,
            inspection: InspectionLevel::None,
            rate_limit_pps: 0,
            priority: 1000,
            rule_id: 0,
            flags: 0,
        }
    }
}

/// Application class for QoE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AppClass {
    /// Voice/VoIP (low latency, low bandwidth)
    Voice = 0,
    /// Video conferencing
    Video = 1,
    /// Web browsing
    Web = 2,
    /// Bulk data transfer
    Bulk = 3,
    /// Real-time gaming
    Gaming = 4,
    /// Interactive (SSH, RDP)
    Interactive = 5,
    /// Unknown/default
    Unknown = 255,
}

impl Default for AppClass {
    fn default() -> Self {
        Self::Unknown
    }
}

/// QoE thresholds per app class
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct QoEThresholds {
    /// Maximum latency in microseconds
    pub max_latency_us: u32,
    /// Maximum jitter in microseconds
    pub max_jitter_us: u32,
    /// Maximum packet loss (0.01% units, so 100 = 1%)
    pub max_loss_permille: u16,
    /// Minimum bandwidth in Kbps
    pub min_bandwidth_kbps: u32,
}

impl QoEThresholds {
    /// Voice thresholds (G.114 compliant)
    pub const VOICE: Self = Self {
        max_latency_us: 150_000,  // 150ms
        max_jitter_us: 30_000,    // 30ms
        max_loss_permille: 10,    // 0.1%
        min_bandwidth_kbps: 100,
    };

    /// Video thresholds
    pub const VIDEO: Self = Self {
        max_latency_us: 200_000,  // 200ms
        max_jitter_us: 50_000,    // 50ms
        max_loss_permille: 20,    // 0.2%
        min_bandwidth_kbps: 5000,
    };

    /// Web thresholds
    pub const WEB: Self = Self {
        max_latency_us: 500_000,  // 500ms
        max_jitter_us: 100_000,   // 100ms
        max_loss_permille: 50,    // 0.5%
        min_bandwidth_kbps: 1000,
    };

    /// Get thresholds for app class
    pub const fn for_class(class: AppClass) -> Self {
        match class {
            AppClass::Voice => Self::VOICE,
            AppClass::Video => Self::VIDEO,
            AppClass::Gaming => Self::VOICE,  // Same as voice
            AppClass::Interactive => Self::VIDEO,
            _ => Self::WEB,
        }
    }
}
