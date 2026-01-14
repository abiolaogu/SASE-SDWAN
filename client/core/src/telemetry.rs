//! Telemetry Collection

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::VecDeque;
use parking_lot::RwLock;

/// Telemetry collector
pub struct TelemetryCollector {
    /// Event queue (for offline queueing)
    queue: Arc<RwLock<VecDeque<TelemetryEvent>>>,
    /// Max queue size
    max_queue_size: usize,
}

impl TelemetryCollector {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(RwLock::new(VecDeque::new())),
            max_queue_size: 10000,
        }
    }

    /// Record connection event
    pub fn record_connection(&self, event: ConnectionEvent) {
        self.queue_event(TelemetryEvent::Connection(event));
    }

    /// Record traffic event
    pub fn record_traffic(&self, event: TrafficEvent) {
        self.queue_event(TelemetryEvent::Traffic(event));
    }

    /// Record security event
    pub fn record_security(&self, event: SecurityEvent) {
        self.queue_event(TelemetryEvent::Security(event));
    }

    /// Record posture event
    pub fn record_posture(&self, event: PostureEvent) {
        self.queue_event(TelemetryEvent::Posture(event));
    }

    fn queue_event(&self, event: TelemetryEvent) {
        let mut queue = self.queue.write();
        if queue.len() >= self.max_queue_size {
            queue.pop_front();  // Drop oldest
        }
        queue.push_back(event);
    }

    /// Flush queue to controller
    pub async fn flush(&self) -> Result<usize, String> {
        let events: Vec<_> = {
            let mut queue = self.queue.write();
            queue.drain(..).collect()
        };

        let count = events.len();
        if count == 0 {
            return Ok(0);
        }

        // In production: send to controller
        tracing::debug!("Flushing {} telemetry events", count);
        
        Ok(count)
    }

    /// Get queue size
    pub fn queue_size(&self) -> usize {
        self.queue.read().len()
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self { Self::new() }
}

/// Telemetry event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryEvent {
    Connection(ConnectionEvent),
    Traffic(TrafficEvent),
    Security(SecurityEvent),
    Posture(PostureEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub event_type: ConnectionEventType,
    pub pop_id: String,
    pub latency_ms: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConnectionEventType {
    Connected,
    Disconnected,
    Reconnected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEvent {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub flows_active: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub destination: String,
    pub action: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecurityEventType {
    ThreatBlocked,
    PolicyViolation,
    CertificateError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureEvent {
    pub is_compliant: bool,
    pub issues: Vec<String>,
    pub timestamp: u64,
}
