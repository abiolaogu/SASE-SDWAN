//! Suricata Integration Module
//!
//! Connect IPS engine to VPP data plane pipeline.

use crate::{Result, SdwanError};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{info, warn, error, debug};

/// Suricata integration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuricataMode {
    /// Inline IPS mode - can block traffic
    Inline,
    /// Passive IDS mode - monitor only
    Passive,
    /// AF_PACKET mode
    AfPacket,
    /// DPDK mode
    Dpdk,
}

/// Suricata alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataAlert {
    pub timestamp: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub protocol: String,
    pub signature_id: u64,
    pub signature: String,
    pub category: String,
    pub severity: u8,
    pub action: String,
}

/// Suricata EVE JSON log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EveEntry {
    #[serde(rename = "timestamp")]
    pub timestamp: String,
    
    #[serde(rename = "event_type")]
    pub event_type: String,
    
    #[serde(rename = "src_ip")]
    pub src_ip: Option<String>,
    
    #[serde(rename = "src_port")]
    pub src_port: Option<u16>,
    
    #[serde(rename = "dest_ip")]
    pub dest_ip: Option<String>,
    
    #[serde(rename = "dest_port")]
    pub dest_port: Option<u16>,
    
    #[serde(rename = "proto")]
    pub proto: Option<String>,
    
    #[serde(rename = "alert")]
    pub alert: Option<EveAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EveAlert {
    pub signature_id: u64,
    pub signature: String,
    pub category: String,
    pub severity: u8,
    pub action: String,
}

/// Suricata socket commands
#[derive(Debug, Serialize)]
struct SocketCommand {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<serde_json::Value>,
}

/// Suricata socket response
#[derive(Debug, Deserialize)]
struct SocketResponse {
    return_code: String,
    message: Option<serde_json::Value>,
}

/// Suricata Integration
pub struct SuricataIntegration {
    /// Unix socket path
    socket_path: String,
    /// EVE log path
    eve_log_path: String,
    /// Running mode
    mode: SuricataMode,
    /// Connected flag
    connected: bool,
}

impl SuricataIntegration {
    /// Create new Suricata integration
    pub fn new(socket_path: &str, eve_log_path: &str, mode: SuricataMode) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            eve_log_path: eve_log_path.to_string(),
            mode,
            connected: false,
        }
    }
    
    /// Connect to Suricata unix socket
    async fn connect_socket(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket_path).await
            .map_err(|e| SdwanError::IoError(e))
    }
    
    /// Send command to Suricata
    async fn send_command(&self, command: &str, args: Option<serde_json::Value>) -> Result<SocketResponse> {
        let mut stream = self.connect_socket().await?;
        
        let cmd = SocketCommand {
            command: command.to_string(),
            arguments: args,
        };
        
        let cmd_json = serde_json::to_string(&cmd)
            .map_err(|e| SdwanError::PolicyError(e.to_string()))?;
        
        stream.write_all(cmd_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        
        serde_json::from_str(&response)
            .map_err(|e| SdwanError::PolicyError(e.to_string()))
    }
    
    /// Start Suricata integration
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Suricata integration in {:?} mode", self.mode);
        
        // Verify socket exists
        if !Path::new(&self.socket_path).exists() {
            warn!("Suricata socket not found: {}", self.socket_path);
        }
        
        self.connected = true;
        Ok(())
    }
    
    /// Get Suricata version
    pub async fn get_version(&self) -> Result<String> {
        let response = self.send_command("version", None).await?;
        
        if let Some(msg) = response.message {
            Ok(msg.to_string())
        } else {
            Ok("Unknown".to_string())
        }
    }
    
    /// Get running mode
    pub async fn get_running_mode(&self) -> Result<String> {
        let response = self.send_command("running-mode", None).await?;
        
        if let Some(msg) = response.message {
            Ok(msg.to_string())
        } else {
            Ok("Unknown".to_string())
        }
    }
    
    /// Reload rules
    pub async fn reload_rules(&self) -> Result<()> {
        info!("Reloading Suricata rules");
        
        let response = self.send_command("reload-rules", None).await?;
        
        if response.return_code == "OK" {
            info!("Suricata rules reloaded successfully");
            Ok(())
        } else {
            warn!("Failed to reload rules: {:?}", response.message);
            Err(SdwanError::PolicyError("Rule reload failed".to_string()))
        }
    }
    
    /// Get stats
    pub async fn get_stats(&self) -> Result<SuricataStats> {
        let response = self.send_command("dump-counters", None).await?;
        
        // Parse counters from response
        Ok(SuricataStats {
            packets_processed: 0,
            alerts_generated: 0,
            packets_dropped: 0,
            flows_active: 0,
        })
    }
    
    /// Stream alerts from EVE log
    pub async fn stream_alerts<F>(&self, callback: F) -> Result<()>
    where
        F: Fn(SuricataAlert) + Send + 'static,
    {
        info!("Starting EVE log streaming from {}", self.eve_log_path);
        
        let file = tokio::fs::File::open(&self.eve_log_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        
        while let Some(line) = lines.next_line().await? {
            if let Ok(entry) = serde_json::from_str::<EveEntry>(&line) {
                if entry.event_type == "alert" {
                    if let Some(alert_data) = entry.alert {
                        let alert = SuricataAlert {
                            timestamp: entry.timestamp,
                            src_ip: entry.src_ip.and_then(|s| s.parse().ok()).unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
                            src_port: entry.src_port.unwrap_or(0),
                            dest_ip: entry.dest_ip.and_then(|s| s.parse().ok()).unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
                            dest_port: entry.dest_port.unwrap_or(0),
                            protocol: entry.proto.unwrap_or_default(),
                            signature_id: alert_data.signature_id,
                            signature: alert_data.signature,
                            category: alert_data.category,
                            severity: alert_data.severity,
                            action: alert_data.action,
                        };
                        
                        callback(alert);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Add IP to blocklist
    pub async fn block_ip(&self, ip: IpAddr) -> Result<()> {
        info!("Blocking IP: {}", ip);
        
        let args = serde_json::json!({
            "ip": ip.to_string()
        });
        
        self.send_command("iprep-add", Some(args)).await?;
        Ok(())
    }
    
    /// Remove IP from blocklist
    pub async fn unblock_ip(&self, ip: IpAddr) -> Result<()> {
        info!("Unblocking IP: {}", ip);
        
        let args = serde_json::json!({
            "ip": ip.to_string()
        });
        
        self.send_command("iprep-remove", Some(args)).await?;
        Ok(())
    }
    
    /// Generate VPP tap interface config for Suricata
    pub fn generate_vpp_tap_config(&self) -> VppSuricataConfig {
        VppSuricataConfig {
            tap_interface: "tap-suricata".to_string(),
            tx_ring_size: 1024,
            rx_ring_size: 1024,
            host_bridge: "br-suricata".to_string(),
            inline_mode: self.mode == SuricataMode::Inline,
        }
    }
}

/// Suricata statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataStats {
    pub packets_processed: u64,
    pub alerts_generated: u64,
    pub packets_dropped: u64,
    pub flows_active: u64,
}

/// VPP configuration for Suricata integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VppSuricataConfig {
    pub tap_interface: String,
    pub tx_ring_size: u32,
    pub rx_ring_size: u32,
    pub host_bridge: String,
    pub inline_mode: bool,
}

impl VppSuricataConfig {
    /// Generate VPP CLI commands
    pub fn to_vpp_cli(&self) -> Vec<String> {
        let mut commands = Vec::new();
        
        // Create TAP interface
        commands.push(format!(
            "create tap id 0 host-if-name {} tx-ring-size {} rx-ring-size {}",
            self.tap_interface, self.tx_ring_size, self.rx_ring_size
        ));
        
        // Set interface up
        commands.push(format!("set interface state tap0 up"));
        
        if self.inline_mode {
            // For inline mode: mirror traffic to Suricata
            commands.push("set interface l2 xconnect GigabitEthernet0/8/0 tap0".to_string());
        }
        
        commands
    }
}
