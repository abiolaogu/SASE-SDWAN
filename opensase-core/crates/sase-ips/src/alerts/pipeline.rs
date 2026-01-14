//! Alert Pipeline
//!
//! Lock-free alert aggregation and batched transmission.

use chrono::{DateTime, Utc};
use crossbeam_channel::{Sender, Receiver, bounded};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Alert priority
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Security alert
#[derive(Clone, Debug)]
pub struct SecurityAlert {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Source IP
    pub src_ip: Option<String>,
    
    /// Source port
    pub src_port: Option<u16>,
    
    /// Destination IP
    pub dst_ip: Option<String>,
    
    /// Destination port
    pub dst_port: Option<u16>,
    
    /// Protocol
    pub protocol: String,
    
    /// Rule SID
    pub sid: u32,
    
    /// Rule message
    pub msg: String,
    
    /// Category
    pub category: String,
    
    /// Priority
    pub priority: AlertPriority,
    
    /// Action taken
    pub action: String,
    
    /// Additional data
    pub payload_excerpt: Option<String>,
    
    /// Tenant ID
    pub tenant_id: Option<u32>,
}

impl SecurityAlert {
    /// Create new alert
    pub fn new(sid: u32, msg: &str, priority: AlertPriority) -> Self {
        Self {
            timestamp: Utc::now(),
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: None,
            protocol: "TCP".into(),
            sid,
            msg: msg.into(),
            category: "unknown".into(),
            priority,
            action: "alert".into(),
            payload_excerpt: None,
            tenant_id: None,
        }
    }
    
    /// Set source
    pub fn with_source(mut self, ip: &str, port: u16) -> Self {
        self.src_ip = Some(ip.into());
        self.src_port = Some(port);
        self
    }
    
    /// Set destination
    pub fn with_destination(mut self, ip: &str, port: u16) -> Self {
        self.dst_ip = Some(ip.into());
        self.dst_port = Some(port);
        self
    }
    
    /// Set category
    pub fn with_category(mut self, category: &str) -> Self {
        self.category = category.into();
        self
    }
    
    /// Set action
    pub fn with_action(mut self, action: &str) -> Self {
        self.action = action.into();
        self
    }
}

/// Alert pipeline statistics
#[derive(Debug, Default)]
pub struct PipelineStats {
    pub alerts_received: AtomicU64,
    pub alerts_sent: AtomicU64,
    pub alerts_dropped: AtomicU64,
    pub batches_sent: AtomicU64,
}

/// Alert pipeline configuration
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Wazuh/SIEM address
    pub siem_address: SocketAddr,
    
    /// Batch size
    pub batch_size: usize,
    
    /// Flush interval (milliseconds)
    pub flush_interval_ms: u64,
    
    /// Queue size
    pub queue_size: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            siem_address: "127.0.0.1:514".parse().unwrap(),
            batch_size: 1000,
            flush_interval_ms: 1000,
            queue_size: 100_000,
        }
    }
}

/// Alert pipeline
pub struct AlertPipeline {
    /// Sender channel
    sender: Sender<SecurityAlert>,
    
    /// Statistics
    stats: Arc<PipelineStats>,
    
    /// Configuration
    config: PipelineConfig,
}

impl AlertPipeline {
    /// Create new pipeline
    pub fn new(config: PipelineConfig) -> Self {
        let (sender, _receiver) = bounded(config.queue_size);
        
        Self {
            sender,
            stats: Arc::new(PipelineStats::default()),
            config,
        }
    }
    
    /// Start the pipeline (async)
    pub async fn start(&self) -> tokio::io::Result<()> {
        let (tx, rx) = bounded::<SecurityAlert>(self.config.queue_size);
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        let config = self.config.clone();
        let stats = self.stats.clone();
        
        tokio::spawn(async move {
            Self::worker_loop(rx, socket, config, stats).await;
        });
        
        Ok(())
    }
    
    /// Worker loop
    async fn worker_loop(
        receiver: Receiver<SecurityAlert>,
        socket: UdpSocket,
        config: PipelineConfig,
        stats: Arc<PipelineStats>,
    ) {
        use super::cef::CefFormatter;
        
        let formatter = CefFormatter::new();
        let mut batch: Vec<String> = Vec::with_capacity(config.batch_size);
        let mut last_flush = std::time::Instant::now();
        
        loop {
            // Try to receive with timeout
            match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(alert) => {
                    let cef = formatter.format(&alert);
                    batch.push(cef);
                    
                    stats.alerts_received.fetch_add(1, Ordering::Relaxed);
                    
                    // Check if batch is full
                    if batch.len() >= config.batch_size {
                        Self::flush_batch(&socket, &mut batch, &config, &stats).await;
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // Check if we need to flush
                    if !batch.is_empty() && 
                       last_flush.elapsed().as_millis() as u64 >= config.flush_interval_ms {
                        Self::flush_batch(&socket, &mut batch, &config, &stats).await;
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // Channel closed, flush and exit
                    if !batch.is_empty() {
                        Self::flush_batch(&socket, &mut batch, &config, &stats).await;
                    }
                    break;
                }
            }
        }
    }
    
    /// Flush batch to SIEM
    async fn flush_batch(
        socket: &UdpSocket,
        batch: &mut Vec<String>,
        config: &PipelineConfig,
        stats: &PipelineStats,
    ) {
        for msg in batch.drain(..) {
            match socket.send_to(msg.as_bytes(), config.siem_address).await {
                Ok(_) => {
                    stats.alerts_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to send alert to SIEM");
                    stats.alerts_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        
        stats.batches_sent.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Send alert
    pub fn send(&self, alert: SecurityAlert) -> Result<(), crossbeam_channel::TrySendError<SecurityAlert>> {
        self.sender.try_send(alert)
    }
    
    /// Get statistics
    pub fn stats(&self) -> &PipelineStats {
        &self.stats
    }
}

impl Default for AlertPipeline {
    fn default() -> Self {
        Self::new(PipelineConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_creation() {
        let alert = SecurityAlert::new(1000001, "Test alert", AlertPriority::High)
            .with_source("192.168.1.1", 12345)
            .with_destination("10.0.0.1", 80)
            .with_category("web-attack");
        
        assert_eq!(alert.sid, 1000001);
        assert_eq!(alert.src_ip, Some("192.168.1.1".into()));
        assert_eq!(alert.priority, AlertPriority::High);
    }
}
