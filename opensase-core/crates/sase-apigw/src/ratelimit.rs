//! Rate Limiting
//!
//! Token bucket, sliding window, and quota-based rate limiting.

use crate::{GatewayError, RateLimitConfig};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Rate limiter with multiple algorithms
pub struct RateLimiter {
    config: RateLimitConfig,
    token_buckets: DashMap<String, TokenBucket>,
    sliding_windows: DashMap<String, SlidingWindow>,
    quotas: DashMap<String, Quota>,
}

/// Rate limit policy
#[derive(Clone, Debug)]
pub struct RateLimitPolicy {
    pub name: String,
    pub algorithm: RateLimitAlgorithm,
    pub requests_per_second: Option<u32>,
    pub requests_per_minute: Option<u32>,
    pub requests_per_hour: Option<u32>,
    pub requests_per_day: Option<u32>,
    pub burst_size: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    LeakyBucket,
}

/// Token bucket implementation
pub struct TokenBucket {
    tokens: AtomicU64,
    max_tokens: u64,
    refill_rate: f64,  // tokens per second
    last_refill: parking_lot::Mutex<Instant>,
}

impl TokenBucket {
    pub fn new(max_tokens: u64, refill_rate: f64) -> Self {
        Self {
            tokens: AtomicU64::new(max_tokens),
            max_tokens,
            refill_rate,
            last_refill: parking_lot::Mutex::new(Instant::now()),
        }
    }
    
    /// Try to consume a token
    pub fn try_acquire(&self) -> bool {
        self.refill();
        
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current == 0 {
                return false;
            }
            
            if self.tokens.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return true;
            }
        }
    }
    
    /// Refill tokens based on elapsed time
    fn refill(&self) {
        let mut last_refill = self.last_refill.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);
        
        let tokens_to_add = (elapsed.as_secs_f64() * self.refill_rate) as u64;
        if tokens_to_add > 0 {
            let current = self.tokens.load(Ordering::Acquire);
            let new_tokens = (current + tokens_to_add).min(self.max_tokens);
            self.tokens.store(new_tokens, Ordering::Release);
            *last_refill = now;
        }
    }
    
    /// Get remaining tokens
    pub fn remaining(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Acquire)
    }
}

/// Sliding window rate limiter
pub struct SlidingWindow {
    window_size: Duration,
    max_requests: u64,
    requests: parking_lot::Mutex<Vec<Instant>>,
}

impl SlidingWindow {
    pub fn new(window_size: Duration, max_requests: u64) -> Self {
        Self {
            window_size,
            max_requests,
            requests: parking_lot::Mutex::new(Vec::new()),
        }
    }
    
    /// Try to record a request
    pub fn try_acquire(&self) -> bool {
        let mut requests = self.requests.lock();
        let now = Instant::now();
        let cutoff = now - self.window_size;
        
        // Remove expired requests
        requests.retain(|&t| t > cutoff);
        
        if requests.len() < self.max_requests as usize {
            requests.push(now);
            true
        } else {
            false
        }
    }
    
    /// Get remaining requests in window
    pub fn remaining(&self) -> u64 {
        let requests = self.requests.lock();
        let now = Instant::now();
        let cutoff = now - self.window_size;
        
        let active = requests.iter().filter(|&&t| t > cutoff).count() as u64;
        self.max_requests.saturating_sub(active)
    }
    
    /// Get reset time
    pub fn reset_at(&self) -> Option<Instant> {
        let requests = self.requests.lock();
        requests.first().map(|&t| t + self.window_size)
    }
}

/// Quota management
pub struct Quota {
    limit: u64,
    used: AtomicU64,
    reset_at: parking_lot::Mutex<Instant>,
    period: Duration,
}

impl Quota {
    pub fn new(limit: u64, period: Duration) -> Self {
        Self {
            limit,
            used: AtomicU64::new(0),
            reset_at: parking_lot::Mutex::new(Instant::now() + period),
            period,
        }
    }
    
    /// Try to use quota
    pub fn try_use(&self, amount: u64) -> bool {
        self.maybe_reset();
        
        loop {
            let current = self.used.load(Ordering::Acquire);
            if current + amount > self.limit {
                return false;
            }
            
            if self.used.compare_exchange_weak(
                current,
                current + amount,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return true;
            }
        }
    }
    
    /// Check and reset if period expired
    fn maybe_reset(&self) {
        let mut reset_at = self.reset_at.lock();
        let now = Instant::now();
        
        if now >= *reset_at {
            self.used.store(0, Ordering::Release);
            *reset_at = now + self.period;
        }
    }
    
    /// Get remaining quota
    pub fn remaining(&self) -> u64 {
        self.maybe_reset();
        self.limit.saturating_sub(self.used.load(Ordering::Acquire))
    }
    
    /// Get usage
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            token_buckets: DashMap::new(),
            sliding_windows: DashMap::new(),
            quotas: DashMap::new(),
        }
    }
    
    /// Check rate limit for a key using token bucket
    pub fn check_token_bucket(&self, key: &str) -> Result<RateLimitResult, GatewayError> {
        let bucket = self.token_buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.requests_per_second as u64 * 2,  // burst
                self.config.requests_per_second as f64,
            )
        });
        
        let allowed = bucket.try_acquire();
        let remaining = bucket.remaining();
        
        Ok(RateLimitResult {
            allowed,
            remaining: remaining as u32,
            limit: self.config.requests_per_second,
            reset_at: None,
            retry_after: if allowed { None } else { Some(1) },
        })
    }
    
    /// Check rate limit for a key using sliding window
    pub fn check_sliding_window(&self, key: &str, window_secs: u64) -> Result<RateLimitResult, GatewayError> {
        let max_requests = match window_secs {
            1 => self.config.requests_per_second,
            60 => self.config.requests_per_minute,
            3600 => self.config.requests_per_hour,
            86400 => self.config.requests_per_day,
            _ => self.config.requests_per_minute,
        };
        
        let window = self.sliding_windows.entry(format!("{}:{}", key, window_secs))
            .or_insert_with(|| {
                SlidingWindow::new(Duration::from_secs(window_secs), max_requests as u64)
            });
        
        let allowed = window.try_acquire();
        let remaining = window.remaining();
        let reset_at = window.reset_at();
        
        Ok(RateLimitResult {
            allowed,
            remaining: remaining as u32,
            limit: max_requests,
            reset_at: reset_at.map(|r| r.elapsed().as_secs() as i64),
            retry_after: if allowed { None } else { Some(1) },
        })
    }
    
    /// Check quota for a key
    pub fn check_quota(&self, key: &str, period_secs: u64) -> Result<RateLimitResult, GatewayError> {
        let limit = match period_secs {
            3600 => self.config.requests_per_hour,
            86400 => self.config.requests_per_day,
            _ => self.config.requests_per_day,
        };
        
        let quota = self.quotas.entry(format!("{}:{}", key, period_secs))
            .or_insert_with(|| {
                Quota::new(limit as u64, Duration::from_secs(period_secs))
            });
        
        let allowed = quota.try_use(1);
        let remaining = quota.remaining();
        
        Ok(RateLimitResult {
            allowed,
            remaining: remaining as u32,
            limit,
            reset_at: None,
            retry_after: if allowed { None } else { Some(period_secs as u32) },
        })
    }
    
    /// Check all rate limits for a key
    pub fn check_all(&self, key: &str) -> Result<RateLimitResult, GatewayError> {
        // Check per-second limit
        let second_result = self.check_token_bucket(key)?;
        if !second_result.allowed {
            return Ok(second_result);
        }
        
        // Check per-minute limit
        let minute_result = self.check_sliding_window(key, 60)?;
        if !minute_result.allowed {
            return Ok(minute_result);
        }
        
        // Check per-hour limit
        let hour_result = self.check_quota(key, 3600)?;
        if !hour_result.allowed {
            return Ok(hour_result);
        }
        
        // Check per-day limit
        let day_result = self.check_quota(key, 86400)?;
        
        Ok(day_result)
    }
    
    /// Get rate limit headers for response
    pub fn get_headers(&self, result: &RateLimitResult) -> Vec<(String, String)> {
        let mut headers = vec![
            ("X-RateLimit-Limit".to_string(), result.limit.to_string()),
            ("X-RateLimit-Remaining".to_string(), result.remaining.to_string()),
        ];
        
        if let Some(reset) = result.reset_at {
            headers.push(("X-RateLimit-Reset".to_string(), reset.to_string()));
        }
        
        if let Some(retry) = result.retry_after {
            headers.push(("Retry-After".to_string(), retry.to_string()));
        }
        
        headers
    }
    
    /// Clear rate limit state for a key
    pub fn clear(&self, key: &str) {
        self.token_buckets.remove(key);
        self.sliding_windows.retain(|k, _| !k.starts_with(key));
        self.quotas.retain(|k, _| !k.starts_with(key));
    }
}

/// Rate limit check result
#[derive(Clone, Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub limit: u32,
    pub reset_at: Option<i64>,
    pub retry_after: Option<u32>,
}
