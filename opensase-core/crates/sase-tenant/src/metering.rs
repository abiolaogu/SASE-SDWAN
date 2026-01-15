//! Usage Metering for Billing Integration
//!
//! Adapted from BSS-OSS usage tracking patterns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Usage metric types
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UsageMetric {
    BandwidthGb,
    ActiveUsers,
    SecurityEventsProcessed,
    SslInspectionGb,
    ApiCalls,
    PolicyEvaluations,
    DlpScans,
    ThreatBlockedCount,
}

/// Usage record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageRecord {
    pub tenant_id: String,
    pub metric: UsageMetric,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Usage meter for tracking consumption
pub struct UsageMeter {
    tenant_id: String,
    counters: HashMap<UsageMetric, Arc<AtomicU64>>,
}

impl UsageMeter {
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            counters: HashMap::new(),
        }
    }
    
    pub fn record(&mut self, metric: UsageMetric, value: u64) {
        let counter = self.counters.entry(metric)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(value, Ordering::Relaxed);
    }
    
    pub fn get(&self, metric: &UsageMetric) -> u64 {
        self.counters.get(metric)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
    
    pub fn snapshot(&self) -> Vec<UsageRecord> {
        let now = Utc::now();
        self.counters.iter()
            .map(|(metric, counter)| UsageRecord {
                tenant_id: self.tenant_id.clone(),
                metric: metric.clone(),
                value: counter.load(Ordering::Relaxed) as f64,
                timestamp: now,
                metadata: HashMap::new(),
            })
            .collect()
    }
    
    pub fn reset(&mut self) {
        for counter in self.counters.values() {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

/// Usage aggregator for billing periods
pub struct UsageAggregator {
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    records: Vec<UsageRecord>,
}

impl UsageAggregator {
    pub fn new(period_start: DateTime<Utc>, period_end: DateTime<Utc>) -> Self {
        Self { period_start, period_end, records: vec![] }
    }
    
    pub fn add_record(&mut self, record: UsageRecord) {
        if record.timestamp >= self.period_start && record.timestamp < self.period_end {
            self.records.push(record);
        }
    }
    
    pub fn summarize(&self, tenant_id: &str) -> HashMap<UsageMetric, f64> {
        let mut summary = HashMap::new();
        for record in self.records.iter().filter(|r| r.tenant_id == tenant_id) {
            *summary.entry(record.metric.clone()).or_insert(0.0) += record.value;
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_usage_meter() {
        let mut meter = UsageMeter::new("tenant_001");
        
        meter.record(UsageMetric::BandwidthGb, 100);
        meter.record(UsageMetric::BandwidthGb, 50);
        meter.record(UsageMetric::ApiCalls, 1000);
        
        assert_eq!(meter.get(&UsageMetric::BandwidthGb), 150);
        assert_eq!(meter.get(&UsageMetric::ApiCalls), 1000);
    }
    
    #[test]
    fn test_usage_snapshot() {
        let mut meter = UsageMeter::new("tenant_001");
        meter.record(UsageMetric::SecurityEventsProcessed, 5000);
        
        let snapshot = meter.snapshot();
        assert!(!snapshot.is_empty());
    }
}
