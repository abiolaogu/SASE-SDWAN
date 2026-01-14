//! Rate limiting middleware

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tower::Layer;

/// Rate limit layer (stub - returns identity layer)
pub fn rate_limit_layer() -> tower::util::Identity {
    tower::util::Identity::new()
}

/// Rate limiter
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if request is allowed
    pub fn check(&self, key: &str) -> RateLimitResult {
        let mut buckets = self.buckets.write();
        
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(self.config.requests_per_second, self.config.burst)
        });

        if bucket.try_acquire() {
            RateLimitResult::Allowed {
                remaining: bucket.available,
                reset_at: bucket.reset_at,
            }
        } else {
            RateLimitResult::Limited {
                retry_after: bucket.reset_at - Instant::now(),
            }
        }
    }
}

/// Rate limit config
#[derive(Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst: 200,
        }
    }
}

/// Token bucket
struct TokenBucket {
    available: u32,
    max: u32,
    refill_rate: u32,
    last_refill: Instant,
    reset_at: Instant,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            available: burst,
            max: burst,
            refill_rate: rate,
            last_refill: Instant::now(),
            reset_at: Instant::now() + Duration::from_secs(1),
        }
    }

    fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.available > 0 {
            self.available -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let tokens = (elapsed.as_secs_f64() * self.refill_rate as f64) as u32;
        
        if tokens > 0 {
            self.available = (self.available + tokens).min(self.max);
            self.last_refill = now;
            self.reset_at = now + Duration::from_secs(1);
        }
    }
}

/// Rate limit result
pub enum RateLimitResult {
    Allowed { remaining: u32, reset_at: Instant },
    Limited { retry_after: Duration },
}
