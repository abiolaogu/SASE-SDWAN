//! API Analytics
//!
//! Collect and analyze API usage metrics.

use crate::AnalyticsConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Analytics collector
pub struct AnalyticsCollector {
    config: AnalyticsConfig,
    requests: parking_lot::RwLock<Vec<RequestLog>>,
    metrics: ApiMetrics,
}

/// Request log entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub service: String,
    pub route: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub latency_ms: u32,
    pub request_size: u64,
    pub response_size: u64,
    pub consumer_id: Option<String>,
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub error: Option<String>,
}

/// API metrics
pub struct ApiMetrics {
    total_requests: AtomicU64,
    total_errors: AtomicU64,
    total_bytes_in: AtomicU64,
    total_bytes_out: AtomicU64,
    status_counts: parking_lot::RwLock<HashMap<u16, u64>>,
    latency_histogram: parking_lot::RwLock<LatencyHistogram>,
    requests_by_service: parking_lot::RwLock<HashMap<String, u64>>,
    requests_by_consumer: parking_lot::RwLock<HashMap<String, u64>>,
    errors_by_service: parking_lot::RwLock<HashMap<String, u64>>,
}

/// Latency histogram
#[derive(Default)]
pub struct LatencyHistogram {
    pub p50: u32,
    pub p90: u32,
    pub p95: u32,
    pub p99: u32,
    pub count: u64,
    pub sum: u64,
    buckets: Vec<u32>,
}

impl LatencyHistogram {
    pub fn new() -> Self {
        Self {
            buckets: Vec::with_capacity(10000),
            ..Default::default()
        }
    }
    
    pub fn record(&mut self, latency_ms: u32) {
        self.buckets.push(latency_ms);
        self.count += 1;
        self.sum += latency_ms as u64;
        
        // Recalculate percentiles periodically
        if self.buckets.len() % 100 == 0 {
            self.calculate_percentiles();
        }
    }
    
    fn calculate_percentiles(&mut self) {
        if self.buckets.is_empty() {
            return;
        }
        
        let mut sorted = self.buckets.clone();
        sorted.sort_unstable();
        
        let len = sorted.len();
        self.p50 = sorted[len * 50 / 100];
        self.p90 = sorted[len * 90 / 100];
        self.p95 = sorted[len * 95 / 100];
        self.p99 = sorted[len * 99 / 100];
    }
    
    pub fn avg(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum as f64 / self.count as f64
        }
    }
}

impl ApiMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            status_counts: parking_lot::RwLock::new(HashMap::new()),
            latency_histogram: parking_lot::RwLock::new(LatencyHistogram::new()),
            requests_by_service: parking_lot::RwLock::new(HashMap::new()),
            requests_by_consumer: parking_lot::RwLock::new(HashMap::new()),
            errors_by_service: parking_lot::RwLock::new(HashMap::new()),
        }
    }
    
    pub fn record(&self, log: &RequestLog) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_in.fetch_add(log.request_size, Ordering::Relaxed);
        self.total_bytes_out.fetch_add(log.response_size, Ordering::Relaxed);
        
        if log.status_code >= 400 {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
            *self.errors_by_service.write()
                .entry(log.service.clone())
                .or_insert(0) += 1;
        }
        
        *self.status_counts.write()
            .entry(log.status_code)
            .or_insert(0) += 1;
        
        self.latency_histogram.write().record(log.latency_ms);
        
        *self.requests_by_service.write()
            .entry(log.service.clone())
            .or_insert(0) += 1;
        
        if let Some(ref consumer) = log.consumer_id {
            *self.requests_by_consumer.write()
                .entry(consumer.clone())
                .or_insert(0) += 1;
        }
    }
}

impl Default for ApiMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyticsCollector {
    /// Create new analytics collector
    pub fn new(config: AnalyticsConfig) -> Self {
        Self {
            config,
            requests: parking_lot::RwLock::new(Vec::new()),
            metrics: ApiMetrics::new(),
        }
    }
    
    /// Record a request
    pub fn record(&self, log: RequestLog) {
        if !self.config.enabled {
            return;
        }
        
        // Apply sampling
        if self.config.sample_rate < 1.0 {
            let sample: f32 = rand::random();
            if sample > self.config.sample_rate {
                return;
            }
        }
        
        // Update metrics
        self.metrics.record(&log);
        
        // Store log
        let mut requests = self.requests.write();
        requests.push(log);
        
        // Trim old entries
        let max_entries = 100000;
        let len = requests.len();
        if len > max_entries {
            requests.drain(0..len - max_entries);
        }
    }
    
    /// Get summary statistics
    pub fn get_summary(&self) -> AnalyticsSummary {
        let histogram = self.metrics.latency_histogram.read();
        
        AnalyticsSummary {
            total_requests: self.metrics.total_requests.load(Ordering::Relaxed),
            total_errors: self.metrics.total_errors.load(Ordering::Relaxed),
            total_bytes_in: self.metrics.total_bytes_in.load(Ordering::Relaxed),
            total_bytes_out: self.metrics.total_bytes_out.load(Ordering::Relaxed),
            avg_latency_ms: histogram.avg(),
            p50_latency_ms: histogram.p50,
            p90_latency_ms: histogram.p90,
            p95_latency_ms: histogram.p95,
            p99_latency_ms: histogram.p99,
            error_rate: self.calculate_error_rate(),
            status_breakdown: self.metrics.status_counts.read().clone(),
            top_services: self.get_top_services(10),
            top_consumers: self.get_top_consumers(10),
        }
    }
    
    /// Get requests by time range
    pub fn get_requests(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<RequestLog> {
        self.requests.read()
            .iter()
            .filter(|r| r.timestamp >= from && r.timestamp <= to)
            .cloned()
            .collect()
    }
    
    /// Get requests by service
    pub fn get_by_service(&self, service: &str) -> Vec<RequestLog> {
        self.requests.read()
            .iter()
            .filter(|r| r.service == service)
            .cloned()
            .collect()
    }
    
    /// Get error requests
    pub fn get_errors(&self) -> Vec<RequestLog> {
        self.requests.read()
            .iter()
            .filter(|r| r.status_code >= 400)
            .cloned()
            .collect()
    }
    
    /// Calculate error rate
    fn calculate_error_rate(&self) -> f64 {
        let total = self.metrics.total_requests.load(Ordering::Relaxed);
        let errors = self.metrics.total_errors.load(Ordering::Relaxed);
        
        if total == 0 {
            0.0
        } else {
            errors as f64 / total as f64 * 100.0
        }
    }
    
    /// Get top services by request count
    fn get_top_services(&self, n: usize) -> Vec<(String, u64)> {
        let mut services: Vec<_> = self.metrics.requests_by_service.read()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        
        services.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        services.truncate(n);
        services
    }
    
    /// Get top consumers by request count
    fn get_top_consumers(&self, n: usize) -> Vec<(String, u64)> {
        let mut consumers: Vec<_> = self.metrics.requests_by_consumer.read()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        
        consumers.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        consumers.truncate(n);
        consumers
    }
    
    /// Export to Prometheus format
    pub fn export_prometheus(&self) -> String {
        let summary = self.get_summary();
        
        let mut output = String::new();
        
        output.push_str(&format!(
            "# HELP osag_requests_total Total number of API requests\n\
             # TYPE osag_requests_total counter\n\
             osag_requests_total {}\n\n",
            summary.total_requests
        ));
        
        output.push_str(&format!(
            "# HELP osag_errors_total Total number of API errors\n\
             # TYPE osag_errors_total counter\n\
             osag_errors_total {}\n\n",
            summary.total_errors
        ));
        
        output.push_str(&format!(
            "# HELP osag_latency_ms API latency in milliseconds\n\
             # TYPE osag_latency_ms summary\n\
             osag_latency_ms{{quantile=\"0.5\"}} {}\n\
             osag_latency_ms{{quantile=\"0.9\"}} {}\n\
             osag_latency_ms{{quantile=\"0.95\"}} {}\n\
             osag_latency_ms{{quantile=\"0.99\"}} {}\n\n",
            summary.p50_latency_ms,
            summary.p90_latency_ms,
            summary.p95_latency_ms,
            summary.p99_latency_ms
        ));
        
        output.push_str(&format!(
            "# HELP osag_bytes_in_total Total bytes received\n\
             # TYPE osag_bytes_in_total counter\n\
             osag_bytes_in_total {}\n\n",
            summary.total_bytes_in
        ));
        
        output.push_str(&format!(
            "# HELP osag_bytes_out_total Total bytes sent\n\
             # TYPE osag_bytes_out_total counter\n\
             osag_bytes_out_total {}\n\n",
            summary.total_bytes_out
        ));
        
        output
    }
}

/// Analytics summary
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyticsSummary {
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: u32,
    pub p90_latency_ms: u32,
    pub p95_latency_ms: u32,
    pub p99_latency_ms: u32,
    pub error_rate: f64,
    pub status_breakdown: HashMap<u16, u64>,
    pub top_services: Vec<(String, u64)>,
    pub top_consumers: Vec<(String, u64)>,
}
