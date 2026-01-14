//! Resource Limits and Quota Enforcement

use crate::model::{TenantId, ResourceLimits};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

/// Quota enforcer
pub struct QuotaEnforcer {
    /// Per-tenant quotas
    quotas: Arc<RwLock<HashMap<TenantId, TenantQuota>>>,
    /// Global fair-share scheduler
    scheduler: FairScheduler,
}

impl QuotaEnforcer {
    pub fn new() -> Self {
        Self {
            quotas: Arc::new(RwLock::new(HashMap::new())),
            scheduler: FairScheduler::new(),
        }
    }

    /// Set limits for tenant
    pub fn set_limits(&self, tenant_id: TenantId, limits: ResourceLimits) {
        let quota = TenantQuota::new(limits);
        self.quotas.write().insert(tenant_id, quota);
    }

    /// Check if bandwidth available
    pub fn check_bandwidth(&self, tenant_id: &TenantId, bytes: u64) -> QuotaResult {
        let mut quotas = self.quotas.write();
        let quota = match quotas.get_mut(tenant_id) {
            Some(q) => q,
            None => return QuotaResult::Denied("Tenant not found".into()),
        };

        quota.bandwidth_bucket.refill();
        
        if quota.bandwidth_bucket.consume(bytes) {
            QuotaResult::Allowed
        } else {
            QuotaResult::Throttled(Duration::from_millis(10))
        }
    }

    /// Check connection limit
    pub fn check_connection(&self, tenant_id: &TenantId) -> QuotaResult {
        let quotas = self.quotas.read();
        let quota = match quotas.get(tenant_id) {
            Some(q) => q,
            None => return QuotaResult::Denied("Tenant not found".into()),
        };

        if quota.active_connections.load(std::sync::atomic::Ordering::Relaxed) 
            < quota.limits.max_connections {
            QuotaResult::Allowed
        } else {
            QuotaResult::Denied("Connection limit reached".into())
        }
    }

    /// Increment connection count
    pub fn connection_opened(&self, tenant_id: &TenantId) {
        if let Some(quota) = self.quotas.read().get(tenant_id) {
            quota.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Decrement connection count
    pub fn connection_closed(&self, tenant_id: &TenantId) {
        if let Some(quota) = self.quotas.read().get(tenant_id) {
            quota.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Check API rate limit
    pub fn check_api_rate(&self, tenant_id: &TenantId) -> QuotaResult {
        let mut quotas = self.quotas.write();
        let quota = match quotas.get_mut(tenant_id) {
            Some(q) => q,
            None => return QuotaResult::Denied("Tenant not found".into()),
        };

        quota.api_bucket.refill();
        
        if quota.api_bucket.consume(1) {
            QuotaResult::Allowed
        } else {
            QuotaResult::RateLimited {
                retry_after: Duration::from_secs(60),
            }
        }
    }

    /// Get usage stats
    pub fn get_usage(&self, tenant_id: &TenantId) -> Option<UsageStats> {
        let quotas = self.quotas.read();
        let quota = quotas.get(tenant_id)?;

        Some(UsageStats {
            bandwidth_used: quota.bandwidth_used.load(std::sync::atomic::Ordering::Relaxed),
            bandwidth_limit: quota.limits.bandwidth_mbps * 1_000_000 / 8,
            connections_active: quota.active_connections.load(std::sync::atomic::Ordering::Relaxed),
            connections_limit: quota.limits.max_connections,
            api_calls_used: quota.api_calls.load(std::sync::atomic::Ordering::Relaxed),
            api_calls_limit: quota.limits.api_rate_limit as u64,
        })
    }
}

impl Default for QuotaEnforcer {
    fn default() -> Self { Self::new() }
}

/// Per-tenant quota state
pub struct TenantQuota {
    pub limits: ResourceLimits,
    pub bandwidth_bucket: TokenBucket,
    pub api_bucket: TokenBucket,
    pub active_connections: std::sync::atomic::AtomicU64,
    pub bandwidth_used: std::sync::atomic::AtomicU64,
    pub api_calls: std::sync::atomic::AtomicU64,
}

impl TenantQuota {
    pub fn new(limits: ResourceLimits) -> Self {
        let bw_rate = limits.bandwidth_mbps * 1_000_000 / 8;  // bytes/sec
        let api_rate = limits.api_rate_limit as u64;
        
        Self {
            limits,
            bandwidth_bucket: TokenBucket::new(bw_rate, bw_rate * 2),
            api_bucket: TokenBucket::new(api_rate / 60, api_rate),  // per second
            active_connections: std::sync::atomic::AtomicU64::new(0),
            bandwidth_used: std::sync::atomic::AtomicU64::new(0),
            api_calls: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// Token bucket
pub struct TokenBucket {
    rate: u64,
    burst: u64,
    tokens: u64,
    last_refill: Instant,
}

impl TokenBucket {
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

    pub fn consume(&mut self, amount: u64) -> bool {
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// Quota result
#[derive(Debug, Clone)]
pub enum QuotaResult {
    Allowed,
    Throttled(Duration),
    RateLimited { retry_after: Duration },
    Denied(String),
}

/// Usage statistics
#[derive(Debug, Clone)]
pub struct UsageStats {
    pub bandwidth_used: u64,
    pub bandwidth_limit: u64,
    pub connections_active: u64,
    pub connections_limit: u64,
    pub api_calls_used: u64,
    pub api_calls_limit: u64,
}

impl UsageStats {
    /// Get bandwidth utilization percentage
    pub fn bandwidth_utilization(&self) -> f64 {
        (self.bandwidth_used as f64 / self.bandwidth_limit as f64) * 100.0
    }

    /// Get connection utilization percentage
    pub fn connection_utilization(&self) -> f64 {
        (self.connections_active as f64 / self.connections_limit as f64) * 100.0
    }
}

/// Fair scheduler across tenants
pub struct FairScheduler {
    weights: HashMap<TenantId, u32>,
}

impl FairScheduler {
    pub fn new() -> Self {
        Self { weights: HashMap::new() }
    }

    pub fn set_weight(&mut self, tenant_id: TenantId, weight: u32) {
        self.weights.insert(tenant_id, weight);
    }

    /// Get scheduling share for tenant (0.0 - 1.0)
    pub fn get_share(&self, tenant_id: &TenantId) -> f64 {
        let weight = self.weights.get(tenant_id).copied().unwrap_or(1);
        let total: u32 = self.weights.values().sum();
        if total == 0 { return 1.0; }
        weight as f64 / total as f64
    }
}

impl Default for FairScheduler {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TenantTier;

    #[test]
    fn test_quota_enforcement() {
        let enforcer = QuotaEnforcer::new();
        let tenant = TenantId::new_v4();
        
        enforcer.set_limits(tenant, ResourceLimits::for_tier(TenantTier::Pro));
        
        // Should allow bandwidth
        let result = enforcer.check_bandwidth(&tenant, 1000);
        assert!(matches!(result, QuotaResult::Allowed));
    }

    #[test]
    fn test_connection_tracking() {
        let enforcer = QuotaEnforcer::new();
        let tenant = TenantId::new_v4();
        
        enforcer.set_limits(tenant, ResourceLimits::for_tier(TenantTier::Free));
        
        enforcer.connection_opened(&tenant);
        enforcer.connection_opened(&tenant);
        
        let usage = enforcer.get_usage(&tenant).unwrap();
        assert_eq!(usage.connections_active, 2);
    }
}
