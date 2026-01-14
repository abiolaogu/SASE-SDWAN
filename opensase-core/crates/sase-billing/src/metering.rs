//! Metering Engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc, NaiveDate, Datelike};

/// Metering engine for usage collection
pub struct MeteringEngine {
    /// Raw events (in production: stream to data store)
    events: Arc<RwLock<Vec<UsageEvent>>>,
    /// Hourly aggregations
    hourly: Arc<RwLock<HashMap<(Uuid, String), AggregatedUsage>>>,
    /// Daily aggregations  
    daily: Arc<RwLock<HashMap<(Uuid, NaiveDate), DailyUsage>>>,
    /// Processed event IDs (for idempotency)
    processed: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl MeteringEngine {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            hourly: Arc::new(RwLock::new(HashMap::new())),
            daily: Arc::new(RwLock::new(HashMap::new())),
            processed: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Record usage event (idempotent)
    pub fn record(&self, event: UsageEvent) {
        // Idempotency check
        if let Some(ref id) = event.idempotency_key {
            if !self.processed.write().insert(id.clone()) {
                tracing::debug!("Duplicate event ignored: {}", id);
                return;
            }
        }

        // Store raw event
        self.events.write().push(event.clone());

        // Update hourly aggregation
        let hour_key = event.timestamp.format("%Y-%m-%d-%H").to_string();
        let key = (event.tenant_id, hour_key);
        let mut hourly = self.hourly.write();
        let agg = hourly.entry(key).or_insert_with(|| AggregatedUsage::new(event.tenant_id));
        agg.add(&event);

        // Update daily aggregation
        let date = event.timestamp.date_naive();
        let daily_key = (event.tenant_id, date);
        let mut daily = self.daily.write();
        let day_agg = daily.entry(daily_key).or_insert_with(|| DailyUsage::new(event.tenant_id, date));
        day_agg.add(&event);
    }

    /// Get monthly usage for tenant
    pub fn get_monthly_usage(&self, tenant_id: Uuid, month: NaiveDate) -> MonthlyUsage {
        let daily = self.daily.read();
        let mut usage = MonthlyUsage::new(tenant_id, month);

        for ((tid, date), day_usage) in daily.iter() {
            if *tid == tenant_id && date.year() == month.year() && date.month() == month.month() {
                usage.add(day_usage);
            }
        }

        usage
    }

    /// Get current usage (for real-time display)
    pub fn get_current_usage(&self, tenant_id: Uuid) -> CurrentUsage {
        let today = Utc::now().date_naive();
        let daily = self.daily.read();
        
        let day_usage = daily.get(&(tenant_id, today)).cloned();
        
        CurrentUsage {
            tenant_id,
            date: today,
            bandwidth_ingress_gb: day_usage.as_ref().map(|d| d.bandwidth_ingress_gb).unwrap_or(0.0),
            bandwidth_egress_gb: day_usage.as_ref().map(|d| d.bandwidth_egress_gb).unwrap_or(0.0),
            active_users: day_usage.as_ref().map(|d| d.active_users).unwrap_or(0),
            active_devices: day_usage.as_ref().map(|d| d.active_devices).unwrap_or(0),
            api_requests: day_usage.as_ref().map(|d| d.api_requests).unwrap_or(0),
        }
    }
}

impl Default for MeteringEngine {
    fn default() -> Self { Self::new() }
}

/// Usage event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEvent {
    pub tenant_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub metric: UsageMetric,
    pub value: f64,
    pub dimensions: HashMap<String, String>,
    pub idempotency_key: Option<String>,
}

/// Usage metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UsageMetric {
    BandwidthIngressGB,
    BandwidthEgressGB,
    ActiveUsers,
    ActiveDevices,
    ProtectedApps,
    SecurityEventsProcessed,
    ZTNASessions,
    APIRequests,
}

/// Aggregated usage (hourly)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedUsage {
    pub tenant_id: Uuid,
    pub bandwidth_ingress_gb: f64,
    pub bandwidth_egress_gb: f64,
    pub active_users: u64,
    pub active_devices: u64,
    pub security_events: u64,
    pub api_requests: u64,
}

impl AggregatedUsage {
    fn new(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            bandwidth_ingress_gb: 0.0,
            bandwidth_egress_gb: 0.0,
            active_users: 0,
            active_devices: 0,
            security_events: 0,
            api_requests: 0,
        }
    }

    fn add(&mut self, event: &UsageEvent) {
        match event.metric {
            UsageMetric::BandwidthIngressGB => self.bandwidth_ingress_gb += event.value,
            UsageMetric::BandwidthEgressGB => self.bandwidth_egress_gb += event.value,
            UsageMetric::ActiveUsers => self.active_users = self.active_users.max(event.value as u64),
            UsageMetric::ActiveDevices => self.active_devices = self.active_devices.max(event.value as u64),
            UsageMetric::SecurityEventsProcessed => self.security_events += event.value as u64,
            UsageMetric::APIRequests => self.api_requests += event.value as u64,
            _ => {}
        }
    }
}

/// Daily usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyUsage {
    pub tenant_id: Uuid,
    pub date: NaiveDate,
    pub bandwidth_ingress_gb: f64,
    pub bandwidth_egress_gb: f64,
    pub peak_users: u64,
    pub peak_devices: u64,
    pub active_users: u64,
    pub active_devices: u64,
    pub security_events: u64,
    pub api_requests: u64,
}

impl DailyUsage {
    fn new(tenant_id: Uuid, date: NaiveDate) -> Self {
        Self {
            tenant_id,
            date,
            bandwidth_ingress_gb: 0.0,
            bandwidth_egress_gb: 0.0,
            peak_users: 0,
            peak_devices: 0,
            active_users: 0,
            active_devices: 0,
            security_events: 0,
            api_requests: 0,
        }
    }

    fn add(&mut self, event: &UsageEvent) {
        match event.metric {
            UsageMetric::BandwidthIngressGB => self.bandwidth_ingress_gb += event.value,
            UsageMetric::BandwidthEgressGB => self.bandwidth_egress_gb += event.value,
            UsageMetric::ActiveUsers => {
                self.peak_users = self.peak_users.max(event.value as u64);
                self.active_users = self.active_users.max(event.value as u64);
            }
            UsageMetric::ActiveDevices => {
                self.peak_devices = self.peak_devices.max(event.value as u64);
                self.active_devices = self.active_devices.max(event.value as u64);
            }
            UsageMetric::SecurityEventsProcessed => self.security_events += event.value as u64,
            UsageMetric::APIRequests => self.api_requests += event.value as u64,
            _ => {}
        }
    }
}

/// Monthly usage summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlyUsage {
    pub tenant_id: Uuid,
    pub month: NaiveDate,
    pub total_bandwidth_ingress_gb: f64,
    pub total_bandwidth_egress_gb: f64,
    pub peak_users: u64,
    pub peak_devices: u64,
    pub total_security_events: u64,
    pub total_api_requests: u64,
}

impl MonthlyUsage {
    fn new(tenant_id: Uuid, month: NaiveDate) -> Self {
        Self {
            tenant_id,
            month,
            total_bandwidth_ingress_gb: 0.0,
            total_bandwidth_egress_gb: 0.0,
            peak_users: 0,
            peak_devices: 0,
            total_security_events: 0,
            total_api_requests: 0,
        }
    }

    fn add(&mut self, day: &DailyUsage) {
        self.total_bandwidth_ingress_gb += day.bandwidth_ingress_gb;
        self.total_bandwidth_egress_gb += day.bandwidth_egress_gb;
        self.peak_users = self.peak_users.max(day.peak_users);
        self.peak_devices = self.peak_devices.max(day.peak_devices);
        self.total_security_events += day.security_events;
        self.total_api_requests += day.api_requests;
    }
}

/// Current usage (real-time)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUsage {
    pub tenant_id: Uuid,
    pub date: NaiveDate,
    pub bandwidth_ingress_gb: f64,
    pub bandwidth_egress_gb: f64,
    pub active_users: u64,
    pub active_devices: u64,
    pub api_requests: u64,
}
