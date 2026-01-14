//! Network Probes (Active and Passive)

use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Active probe types
#[derive(Debug, Clone)]
pub enum ProbeType {
    /// ICMP ping
    Icmp,
    /// TCP SYN (connection test)
    TcpSyn { port: u16 },
    /// HTTP(S) request
    Http { url: String, method: String },
    /// Application-specific
    Application { app: String, endpoint: String },
}

/// Probe result
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub probe_type: ProbeType,
    pub target: String,
    pub success: bool,
    pub rtt: Duration,
    pub timestamp: u64,
    pub error: Option<String>,
}

/// Probe scheduler
pub struct ProbeScheduler {
    probes: Vec<ProbeConfig>,
}

impl ProbeScheduler {
    pub fn new() -> Self {
        Self { probes: Vec::new() }
    }

    /// Add probe
    pub fn add(&mut self, config: ProbeConfig) {
        self.probes.push(config);
    }

    /// Run single probe
    pub async fn run_probe(&self, probe_type: &ProbeType, target: &str) -> ProbeResult {
        let start = Instant::now();
        
        let (success, error) = match probe_type {
            ProbeType::Icmp => self.probe_icmp(target).await,
            ProbeType::TcpSyn { port } => self.probe_tcp(target, *port).await,
            ProbeType::Http { url, .. } => self.probe_http(url).await,
            ProbeType::Application { .. } => self.probe_app().await,
        };

        ProbeResult {
            probe_type: probe_type.clone(),
            target: target.to_string(),
            success,
            rtt: start.elapsed(),
            timestamp: now(),
            error,
        }
    }

    async fn probe_icmp(&self, _target: &str) -> (bool, Option<String>) {
        // Simulated ICMP ping
        sleep(Duration::from_millis(5)).await;
        (true, None)
    }

    async fn probe_tcp(&self, _target: &str, _port: u16) -> (bool, Option<String>) {
        // Simulated TCP SYN
        sleep(Duration::from_millis(10)).await;
        (true, None)
    }

    async fn probe_http(&self, _url: &str) -> (bool, Option<String>) {
        // Simulated HTTP probe
        sleep(Duration::from_millis(50)).await;
        (true, None)
    }

    async fn probe_app(&self) -> (bool, Option<String>) {
        // Simulated app probe
        sleep(Duration::from_millis(100)).await;
        (true, None)
    }
}

impl Default for ProbeScheduler {
    fn default() -> Self { Self::new() }
}

/// Probe configuration
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub name: String,
    pub probe_type: ProbeType,
    pub target: String,
    pub interval: Duration,
    pub timeout: Duration,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
