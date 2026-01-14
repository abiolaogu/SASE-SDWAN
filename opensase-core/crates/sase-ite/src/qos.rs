//! QoS and Traffic Shaping

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex;

/// Hierarchical Token Bucket for fair bandwidth allocation
pub struct HierarchicalTokenBucket {
    /// Root bucket
    root: Bucket,
    /// Per-customer buckets (customer_id → bucket)
    customers: HashMap<String, Bucket>,
    /// Per-class buckets within each customer
    classes: HashMap<(String, QosClass), Bucket>,
}

impl HierarchicalTokenBucket {
    pub fn new(total_rate: u64) -> Self {
        Self {
            root: Bucket::new(total_rate, total_rate * 2),
            customers: HashMap::new(),
            classes: HashMap::new(),
        }
    }

    /// Add customer with guaranteed rate
    pub fn add_customer(&mut self, customer_id: &str, guaranteed_rate: u64, burst: u64) {
        self.customers.insert(
            customer_id.to_string(),
            Bucket::new(guaranteed_rate, burst),
        );
    }

    /// Add class within customer
    pub fn add_class(&mut self, customer_id: &str, class: QosClass, rate: u64) {
        self.classes.insert(
            (customer_id.to_string(), class),
            Bucket::new(rate, rate * 2),
        );
    }

    /// Check if packet can be sent
    pub fn allow(&mut self, customer_id: &str, class: QosClass, bytes: u64) -> bool {
        // Check root
        if !self.root.consume(bytes) {
            return false;
        }

        // Check customer bucket
        if let Some(bucket) = self.customers.get_mut(customer_id) {
            if !bucket.consume(bytes) {
                self.root.refund(bytes);  // Refund root
                return false;
            }
        }

        // Check class bucket
        if let Some(bucket) = self.classes.get_mut(&(customer_id.to_string(), class)) {
            if !bucket.consume(bytes) {
                // Refund
                if let Some(cust) = self.customers.get_mut(customer_id) {
                    cust.refund(bytes);
                }
                self.root.refund(bytes);
                return false;
            }
        }

        true
    }

    /// Refill buckets (call periodically)
    pub fn refill(&mut self) {
        self.root.refill();
        for bucket in self.customers.values_mut() {
            bucket.refill();
        }
        for bucket in self.classes.values_mut() {
            bucket.refill();
        }
    }
}

/// Token bucket
#[derive(Debug)]
pub struct Bucket {
    rate: u64,          // tokens per second
    burst: u64,         // max tokens
    tokens: u64,        // current tokens
    last_refill: Instant,
}

impl Bucket {
    pub fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    pub fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed();
        let new_tokens = (elapsed.as_secs_f64() * self.rate as f64) as u64;
        self.tokens = (self.tokens + new_tokens).min(self.burst);
        self.last_refill = Instant::now();
    }

    pub fn consume(&mut self, bytes: u64) -> bool {
        self.refill();
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    pub fn refund(&mut self, bytes: u64) {
        self.tokens = (self.tokens + bytes).min(self.burst);
    }
}

/// QoS class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QosClass {
    Expedited,   // EF - highest priority
    Assured1,    // AF4 - voice
    Assured2,    // AF3 - video
    Assured3,    // AF2 - interactive
    Assured4,    // AF1 - bulk
    BestEffort,  // BE - default
}

impl QosClass {
    pub fn from_dscp(dscp: u8) -> Self {
        match dscp {
            46 => Self::Expedited,
            34..=38 => Self::Assured1,
            26..=30 => Self::Assured2,
            18..=22 => Self::Assured3,
            10..=14 => Self::Assured4,
            _ => Self::BestEffort,
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            Self::Expedited => 7,
            Self::Assured1 => 6,
            Self::Assured2 => 5,
            Self::Assured3 => 4,
            Self::Assured4 => 3,
            Self::BestEffort => 0,
        }
    }
}

/// Traffic shaper
pub struct TrafficShaper {
    htb: Mutex<HierarchicalTokenBucket>,
    burst_allowance: Duration,
}

impl TrafficShaper {
    pub fn new(total_rate_mbps: u64) -> Self {
        let rate_bytes = total_rate_mbps * 1_000_000 / 8;
        Self {
            htb: Mutex::new(HierarchicalTokenBucket::new(rate_bytes)),
            burst_allowance: Duration::from_millis(100),
        }
    }

    /// Shape packet
    pub fn shape(&self, customer_id: &str, class: QosClass, bytes: u64) -> ShapeResult {
        let mut htb = self.htb.lock();
        
        if htb.allow(customer_id, class, bytes) {
            ShapeResult::Allow
        } else {
            // Check if high-priority burst
            if class.priority() >= 6 {
                ShapeResult::Delay(Duration::from_micros(100))
            } else {
                ShapeResult::Drop
            }
        }
    }
}

/// Shape result
#[derive(Debug, Clone)]
pub enum ShapeResult {
    Allow,
    Delay(Duration),
    Drop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = Bucket::new(1000, 2000);
        assert!(bucket.consume(1500));
        assert!(bucket.consume(400));
        assert!(!bucket.consume(200));  // Exhausted
    }

    #[test]
    fn test_qos_class() {
        assert_eq!(QosClass::from_dscp(46), QosClass::Expedited);
        assert_eq!(QosClass::from_dscp(26), QosClass::Assured2);
        assert_eq!(QosClass::from_dscp(0), QosClass::BestEffort);
    }
}
