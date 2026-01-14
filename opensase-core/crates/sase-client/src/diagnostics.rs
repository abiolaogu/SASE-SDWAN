//! Diagnostics and Troubleshooting
//!
//! Network diagnostics, logging, and issue reporting.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub struct DiagnosticsService {
    logs: parking_lot::RwLock<VecDeque<LogEntry>>,
    max_logs: usize,
    network_tests: parking_lot::RwLock<Vec<NetworkTestResult>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub component: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkTestResult {
    pub test_name: String,
    pub success: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticReport {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub client_version: String,
    pub platform: crate::PlatformInfo,
    pub connection_status: crate::ConnectionStatus,
    pub posture: Option<crate::posture::PostureResult>,
    pub network_tests: Vec<NetworkTestResult>,
    pub recent_logs: Vec<LogEntry>,
    pub system_info: SystemInfo,
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub cpu_count: usize,
    pub memory_total_mb: u64,
    pub memory_used_mb: u64,
    pub disk_free_gb: u64,
    pub uptime_secs: u64,
}

impl DiagnosticsService {
    pub fn new(max_logs: usize) -> Self {
        Self {
            logs: parking_lot::RwLock::new(VecDeque::with_capacity(max_logs)),
            max_logs,
            network_tests: parking_lot::RwLock::new(Vec::new()),
        }
    }
    
    pub fn log(&self, level: LogLevel, component: &str, message: &str) {
        let entry = LogEntry {
            timestamp: chrono::Utc::now(),
            level,
            component: component.to_string(),
            message: message.to_string(),
        };
        
        let mut logs = self.logs.write();
        if logs.len() >= self.max_logs {
            logs.pop_front();
        }
        logs.push_back(entry);
    }
    
    pub fn info(&self, component: &str, message: &str) {
        self.log(LogLevel::Info, component, message);
    }
    
    pub fn warn(&self, component: &str, message: &str) {
        self.log(LogLevel::Warn, component, message);
    }
    
    pub fn error(&self, component: &str, message: &str) {
        self.log(LogLevel::Error, component, message);
    }
    
    pub fn get_logs(&self, level: Option<LogLevel>, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.read();
        logs.iter()
            .filter(|l| level.map(|lvl| l.level == lvl).unwrap_or(true))
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
    
    /// Run network diagnostics
    pub async fn run_network_tests(&self, server_url: &str) -> Vec<NetworkTestResult> {
        let mut results = Vec::new();
        
        // Test 1: DNS resolution
        results.push(self.test_dns(server_url).await);
        
        // Test 2: HTTP connectivity
        results.push(self.test_http(server_url).await);
        
        // Test 3: WireGuard port
        results.push(self.test_wireguard_port(server_url).await);
        
        // Test 4: Internet connectivity
        results.push(self.test_internet().await);
        
        // Test 5: Latency
        results.push(self.test_latency(server_url).await);
        
        *self.network_tests.write() = results.clone();
        results
    }
    
    async fn test_dns(&self, server_url: &str) -> NetworkTestResult {
        let host = url::Url::parse(server_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_default();
        
        let start = std::time::Instant::now();
        
        match tokio::net::lookup_host(format!("{}:443", host)).await {
            Ok(_) => NetworkTestResult {
                test_name: "DNS Resolution".to_string(),
                success: true,
                latency_ms: Some(start.elapsed().as_millis() as u32),
                error: None,
                timestamp: chrono::Utc::now(),
            },
            Err(e) => NetworkTestResult {
                test_name: "DNS Resolution".to_string(),
                success: false,
                latency_ms: None,
                error: Some(e.to_string()),
                timestamp: chrono::Utc::now(),
            },
        }
    }
    
    async fn test_http(&self, server_url: &str) -> NetworkTestResult {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        
        let start = std::time::Instant::now();
        
        match client.get(&format!("{}/health", server_url)).send().await {
            Ok(resp) if resp.status().is_success() => NetworkTestResult {
                test_name: "HTTP Connectivity".to_string(),
                success: true,
                latency_ms: Some(start.elapsed().as_millis() as u32),
                error: None,
                timestamp: chrono::Utc::now(),
            },
            Ok(resp) => NetworkTestResult {
                test_name: "HTTP Connectivity".to_string(),
                success: false,
                latency_ms: Some(start.elapsed().as_millis() as u32),
                error: Some(format!("HTTP {}", resp.status())),
                timestamp: chrono::Utc::now(),
            },
            Err(e) => NetworkTestResult {
                test_name: "HTTP Connectivity".to_string(),
                success: false,
                latency_ms: None,
                error: Some(e.to_string()),
                timestamp: chrono::Utc::now(),
            },
        }
    }
    
    async fn test_wireguard_port(&self, server_url: &str) -> NetworkTestResult {
        let host = url::Url::parse(server_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_default();
        
        // WireGuard typically uses UDP 51820
        let addr = format!("{}:51820", host);
        
        let start = std::time::Instant::now();
        
        match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => {
                match socket.connect(&addr).await {
                    Ok(_) => NetworkTestResult {
                        test_name: "WireGuard Port (UDP 51820)".to_string(),
                        success: true,
                        latency_ms: Some(start.elapsed().as_millis() as u32),
                        error: None,
                        timestamp: chrono::Utc::now(),
                    },
                    Err(e) => NetworkTestResult {
                        test_name: "WireGuard Port (UDP 51820)".to_string(),
                        success: false,
                        latency_ms: None,
                        error: Some(e.to_string()),
                        timestamp: chrono::Utc::now(),
                    },
                }
            }
            Err(e) => NetworkTestResult {
                test_name: "WireGuard Port (UDP 51820)".to_string(),
                success: false,
                latency_ms: None,
                error: Some(e.to_string()),
                timestamp: chrono::Utc::now(),
            },
        }
    }
    
    async fn test_internet(&self) -> NetworkTestResult {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        
        let start = std::time::Instant::now();
        
        match client.get("https://1.1.1.1/dns-query").send().await {
            Ok(_) => NetworkTestResult {
                test_name: "Internet Connectivity".to_string(),
                success: true,
                latency_ms: Some(start.elapsed().as_millis() as u32),
                error: None,
                timestamp: chrono::Utc::now(),
            },
            Err(e) => NetworkTestResult {
                test_name: "Internet Connectivity".to_string(),
                success: false,
                latency_ms: None,
                error: Some(e.to_string()),
                timestamp: chrono::Utc::now(),
            },
        }
    }
    
    async fn test_latency(&self, server_url: &str) -> NetworkTestResult {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        
        let mut latencies = Vec::new();
        
        for _ in 0..3 {
            let start = std::time::Instant::now();
            if client.get(&format!("{}/health", server_url)).send().await.is_ok() {
                latencies.push(start.elapsed().as_millis() as u32);
            }
        }
        
        if latencies.is_empty() {
            NetworkTestResult {
                test_name: "Latency Test".to_string(),
                success: false,
                latency_ms: None,
                error: Some("No responses received".to_string()),
                timestamp: chrono::Utc::now(),
            }
        } else {
            let avg_latency = latencies.iter().sum::<u32>() / latencies.len() as u32;
            NetworkTestResult {
                test_name: "Latency Test".to_string(),
                success: true,
                latency_ms: Some(avg_latency),
                error: None,
                timestamp: chrono::Utc::now(),
            }
        }
    }
    
    /// Generate full diagnostic report
    pub async fn generate_report(
        &self,
        client: &crate::SaseClient,
    ) -> DiagnosticReport {
        let sys = sysinfo::System::new_all();
        
        DiagnosticReport {
            generated_at: chrono::Utc::now(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: crate::PlatformInfo::detect(),
            connection_status: client.status(),
            posture: Some(client.refresh_posture().await),
            network_tests: self.network_tests.read().clone(),
            recent_logs: self.get_logs(None, 100),
            system_info: SystemInfo {
                hostname: hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_default(),
                cpu_count: sys.cpus().len(),
                memory_total_mb: sys.total_memory() / 1024 / 1024,
                memory_used_mb: sys.used_memory() / 1024 / 1024,
                disk_free_gb: sysinfo::Disks::new_with_refreshed_list()
                    .iter()
                    .map(|d| d.available_space())
                    .sum::<u64>() / 1024 / 1024 / 1024,
                uptime_secs: sysinfo::System::uptime(),
            },
        }
    }
    
    /// Export logs to file
    pub fn export_logs(&self, path: &std::path::Path) -> std::io::Result<()> {
        let logs = self.logs.read();
        let content = logs.iter()
            .map(|l| format!(
                "[{}] {} [{}] {}",
                l.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                format!("{:?}", l.level).to_uppercase(),
                l.component,
                l.message
            ))
            .collect::<Vec<_>>()
            .join("\n");
        
        std::fs::write(path, content)
    }
}

impl Default for DiagnosticsService {
    fn default() -> Self { Self::new(1000) }
}
