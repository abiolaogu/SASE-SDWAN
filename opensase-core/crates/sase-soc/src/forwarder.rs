//! Multi-SIEM Forwarder
//!
//! High-throughput event forwarding with retry and buffering.

use crate::{SecurityEvent, Severity};
use crate::normalize::CefEvent;
use std::collections::VecDeque;

pub struct SiemForwarder {
    outputs: Vec<Box<dyn SiemOutput>>,
    retry_queue: parking_lot::RwLock<VecDeque<RetryItem>>,
    buffer: parking_lot::RwLock<Vec<SecurityEvent>>,
    config: ForwarderConfig,
    stats: ForwarderStats,
}

#[derive(Clone)]
pub struct ForwarderConfig {
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub buffer_size: usize,
}

impl Default for ForwarderConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            flush_interval_ms: 1000,
            max_retries: 3,
            retry_delay_ms: 5000,
            buffer_size: 10000,
        }
    }
}

struct ForwarderStats {
    events_sent: std::sync::atomic::AtomicU64,
    events_failed: std::sync::atomic::AtomicU64,
    retries: std::sync::atomic::AtomicU64,
}

struct RetryItem {
    event: SecurityEvent,
    output_name: String,
    attempts: u32,
    next_retry: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventFormat {
    Cef,    // Common Event Format
    Leef,   // Log Event Extended Format
    Json,   // Generic JSON
    Ecs,    // Elastic Common Schema
    Ocsf,   // Open Cybersecurity Schema Framework
}

#[async_trait::async_trait]
pub trait SiemOutput: Send + Sync {
    async fn send(&self, event: &SecurityEvent) -> Result<(), ForwardError>;
    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<(), ForwardError>;
    fn name(&self) -> &str;
    fn format(&self) -> EventFormat;
    async fn health_check(&self) -> bool;
}

impl SiemForwarder {
    pub fn new(config: ForwarderConfig) -> Self {
        Self {
            outputs: Vec::new(),
            retry_queue: parking_lot::RwLock::new(VecDeque::new()),
            buffer: parking_lot::RwLock::new(Vec::with_capacity(config.buffer_size)),
            config,
            stats: ForwarderStats {
                events_sent: std::sync::atomic::AtomicU64::new(0),
                events_failed: std::sync::atomic::AtomicU64::new(0),
                retries: std::sync::atomic::AtomicU64::new(0),
            },
        }
    }
    
    pub fn add_output(&mut self, output: Box<dyn SiemOutput>) {
        tracing::info!("Adding SIEM output: {}", output.name());
        self.outputs.push(output);
    }
    
    /// Forward event to all outputs
    pub async fn forward(&self, event: &SecurityEvent) {
        for output in &self.outputs {
            match output.send(event).await {
                Ok(_) => {
                    self.stats.events_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!("Failed to send to {}: {}", output.name(), e);
                    self.queue_retry(event.clone(), output.name());
                }
            }
        }
    }
    
    /// Buffer event for batch sending
    pub fn buffer(&self, event: SecurityEvent) {
        let mut buf = self.buffer.write();
        if buf.len() < self.config.buffer_size {
            buf.push(event);
        }
        
        if buf.len() >= self.config.batch_size {
            // Trigger flush
            drop(buf);
            tokio::spawn({
                let this = self.clone_stats_only();
                async move {
                    // Flush would happen here
                }
            });
        }
    }
    
    fn clone_stats_only(&self) -> ForwarderStatsClone {
        ForwarderStatsClone {
            events_sent: self.stats.events_sent.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
    
    /// Flush buffered events
    pub async fn flush(&self) {
        let events: Vec<SecurityEvent> = {
            let mut buf = self.buffer.write();
            std::mem::take(&mut *buf)
        };
        
        if events.is_empty() { return; }
        
        for output in &self.outputs {
            if let Err(e) = output.send_batch(&events).await {
                tracing::warn!("Batch send failed to {}: {}", output.name(), e);
                for event in &events {
                    self.queue_retry(event.clone(), output.name());
                }
            } else {
                self.stats.events_sent.fetch_add(events.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    
    fn queue_retry(&self, event: SecurityEvent, output_name: &str) {
        let mut queue = self.retry_queue.write();
        queue.push_back(RetryItem {
            event,
            output_name: output_name.to_string(),
            attempts: 1,
            next_retry: chrono::Utc::now() + chrono::Duration::milliseconds(self.config.retry_delay_ms as i64),
        });
        self.stats.events_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    /// Process retry queue
    pub async fn process_retries(&self) {
        let now = chrono::Utc::now();
        let mut to_retry = Vec::new();
        
        {
            let mut queue = self.retry_queue.write();
            while let Some(item) = queue.front() {
                if item.next_retry <= now {
                    to_retry.push(queue.pop_front().unwrap());
                } else {
                    break;
                }
            }
        }
        
        for mut item in to_retry {
            let output = self.outputs.iter().find(|o| o.name() == item.output_name);
            if let Some(output) = output {
                match output.send(&item.event).await {
                    Ok(_) => {
                        self.stats.events_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.stats.retries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(_) if item.attempts < self.config.max_retries => {
                        item.attempts += 1;
                        item.next_retry = chrono::Utc::now() + chrono::Duration::milliseconds(
                            self.config.retry_delay_ms as i64 * item.attempts as i64
                        );
                        self.retry_queue.write().push_back(item);
                    }
                    Err(e) => {
                        tracing::error!("Gave up on event after {} retries: {}", item.attempts, e);
                    }
                }
            }
        }
    }
    
    pub fn stats(&self) -> ForwarderMetrics {
        ForwarderMetrics {
            events_sent: self.stats.events_sent.load(std::sync::atomic::Ordering::Relaxed),
            events_failed: self.stats.events_failed.load(std::sync::atomic::Ordering::Relaxed),
            retries: self.stats.retries.load(std::sync::atomic::Ordering::Relaxed),
            buffer_size: self.buffer.read().len(),
            retry_queue_size: self.retry_queue.read().len(),
        }
    }
}

struct ForwarderStatsClone {
    events_sent: u64,
}

#[derive(Clone, serde::Serialize)]
pub struct ForwarderMetrics {
    pub events_sent: u64,
    pub events_failed: u64,
    pub retries: u64,
    pub buffer_size: usize,
    pub retry_queue_size: usize,
}

#[derive(Debug)]
pub enum ForwardError {
    ConnectionFailed(String),
    Timeout,
    RateLimited,
    InvalidResponse(String),
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            Self::Timeout => write!(f, "Timeout"),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::InvalidResponse(e) => write!(f, "Invalid response: {}", e),
        }
    }
}

impl std::error::Error for ForwardError {}

// ECS (Elastic Common Schema) converter
pub fn to_ecs(event: &SecurityEvent) -> serde_json::Value {
    serde_json::json!({
        "@timestamp": event.timestamp.to_rfc3339(),
        "event": {
            "id": event.id,
            "kind": "event",
            "category": [format!("{:?}", event.event_type).to_lowercase()],
            "severity": match event.severity {
                Severity::Info => 1,
                Severity::Low => 2,
                Severity::Medium => 3,
                Severity::High => 4,
                Severity::Critical => 5,
            },
        },
        "message": event.description,
        "source": {
            "address": event.source.ip,
        },
        "host": {
            "name": event.source.host,
        },
        "tags": event.tags,
    })
}

// OCSF (Open Cybersecurity Schema Framework) converter
pub fn to_ocsf(event: &SecurityEvent) -> serde_json::Value {
    serde_json::json!({
        "class_uid": 1001, // Security Finding
        "class_name": "Security Finding",
        "severity_id": match event.severity {
            Severity::Info => 1,
            Severity::Low => 2,
            Severity::Medium => 3,
            Severity::High => 4,
            Severity::Critical => 5,
        },
        "time": event.timestamp.timestamp_millis(),
        "message": event.description,
        "finding_info": {
            "uid": event.id,
            "title": format!("{:?}", event.event_type),
        },
        "metadata": {
            "product": {
                "name": "OpenSASE",
                "vendor_name": "OpenSASE",
            },
            "version": "1.0.0",
        },
    })
}

// LEEF (Log Event Extended Format) converter
pub fn to_leef(event: &SecurityEvent) -> String {
    format!(
        "LEEF:2.0|OpenSASE|SASE|1.0|{}|devTime={}\tsev={}\tmsg={}",
        format!("{:?}", event.event_type),
        event.timestamp.format("%b %d %Y %H:%M:%S"),
        match event.severity {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 8,
            Severity::Critical => 10,
        },
        event.description.replace('\t', " ").replace('\n', " ")
    )
}
