//! Value Objects - Immutable domain primitives with validation
//!
//! Value Objects are:
//! - Immutable
//! - Comparable by value (not identity)
//! - Self-validating
//! - Side-effect free

use serde::{Deserialize, Serialize};
use std::fmt;

/// Policy identifier (Value Object)
/// 
/// # Invariants
/// - Must be non-empty
/// - Max 64 characters
/// - Alphanumeric with hyphens only
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(String);

impl PolicyId {
    /// Create new policy ID with validation
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        
        if id.is_empty() {
            return Err(DomainError::InvalidPolicyId("cannot be empty".into()));
        }
        if id.len() > 64 {
            return Err(DomainError::InvalidPolicyId("max 64 characters".into()));
        }
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(DomainError::InvalidPolicyId("alphanumeric only".into()));
        }
        
        Ok(Self(id))
    }

    /// Get inner value
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Flow identifier (Value Object)
/// 
/// Uniquely identifies a network flow using 5-tuple hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(u64);

impl FlowId {
    /// Create from hash
    pub const fn from_hash(hash: u64) -> Self {
        Self(hash)
    }

    /// Get hash value
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Site identifier (Value Object)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SiteId(String);

impl SiteId {
    /// Create new site ID
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        if id.is_empty() {
            return Err(DomainError::InvalidSiteId("cannot be empty".into()));
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// User identifier (Value Object)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(String);

impl UserId {
    /// Create new user ID
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        if id.is_empty() {
            return Err(DomainError::InvalidUserId("cannot be empty".into()));
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// QoE Score (Value Object)
/// 
/// # Invariants
/// - Range: 0.0 to 1.0
/// - Higher is better
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Score(f32);

impl Score {
    /// Create score with validation
    pub fn new(value: f32) -> Result<Self, DomainError> {
        if value < 0.0 || value > 1.0 {
            return Err(DomainError::InvalidScore(
                format!("must be 0.0-1.0, got {}", value)
            ));
        }
        Ok(Self(value))
    }

    /// Create score clamping to valid range
    pub fn clamped(value: f32) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    /// Get value
    pub fn value(&self) -> f32 {
        self.0
    }

    /// Perfect score
    pub const fn perfect() -> Self {
        Self(1.0)
    }

    /// Zero score
    pub const fn zero() -> Self {
        Self(0.0)
    }

    /// Check if meets threshold
    pub fn meets_threshold(&self, threshold: f32) -> bool {
        self.0 >= threshold
    }
}

impl Default for Score {
    fn default() -> Self {
        Self(0.5)
    }
}

/// Latency value object (microseconds)
/// 
/// # Invariants
/// - Non-negative
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Latency(u32);

impl Latency {
    /// Create from microseconds
    pub const fn from_micros(us: u32) -> Self {
        Self(us)
    }

    /// Create from milliseconds
    pub const fn from_millis(ms: u32) -> Self {
        Self(ms * 1000)
    }

    /// Get as microseconds
    pub const fn as_micros(&self) -> u32 {
        self.0
    }

    /// Get as milliseconds
    pub const fn as_millis(&self) -> u32 {
        self.0 / 1000
    }

    /// Check if within SLA
    pub fn within_sla(&self, max: Latency) -> bool {
        self.0 <= max.0
    }
}

/// IP Address (Value Object with IPv4/IPv6 support)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddress {
    V4(u32),
    V6(u128),
}

impl IpAddress {
    /// Create from IPv4 octets
    pub const fn v4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self::V4(u32::from_be_bytes([a, b, c, d]))
    }

    /// Check if private address
    pub fn is_private(&self) -> bool {
        match self {
            Self::V4(ip) => {
                let bytes = ip.to_be_bytes();
                bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
            }
            Self::V6(_) => false,  // Simplified
        }
    }
}

/// Domain errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum DomainError {
    #[error("invalid policy ID: {0}")]
    InvalidPolicyId(String),
    
    #[error("invalid site ID: {0}")]
    InvalidSiteId(String),
    
    #[error("invalid user ID: {0}")]
    InvalidUserId(String),
    
    #[error("invalid score: {0}")]
    InvalidScore(String),
    
    #[error("invariant violation: {0}")]
    InvariantViolation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // TDD: Tests written first, then implementation

    #[test]
    fn test_policy_id_valid() {
        let id = PolicyId::new("my-policy-1").unwrap();
        assert_eq!(id.as_str(), "my-policy-1");
    }

    #[test]
    fn test_policy_id_empty_fails() {
        assert!(PolicyId::new("").is_err());
    }

    #[test]
    fn test_policy_id_too_long_fails() {
        let long = "a".repeat(65);
        assert!(PolicyId::new(long).is_err());
    }

    #[test]
    fn test_score_validation() {
        assert!(Score::new(0.5).is_ok());
        assert!(Score::new(0.0).is_ok());
        assert!(Score::new(1.0).is_ok());
        assert!(Score::new(-0.1).is_err());
        assert!(Score::new(1.1).is_err());
    }

    #[test]
    fn test_score_clamped() {
        assert_eq!(Score::clamped(1.5).value(), 1.0);
        assert_eq!(Score::clamped(-0.5).value(), 0.0);
    }

    #[test]
    fn test_latency() {
        let lat = Latency::from_millis(100);
        assert_eq!(lat.as_micros(), 100_000);
        assert!(lat.within_sla(Latency::from_millis(150)));
        assert!(!lat.within_sla(Latency::from_millis(50)));
    }

    #[test]
    fn test_ip_private() {
        assert!(IpAddress::v4(192, 168, 1, 1).is_private());
        assert!(IpAddress::v4(10, 0, 0, 1).is_private());
        assert!(!IpAddress::v4(8, 8, 8, 8).is_private());
    }
}
