//! XDP First-Line Defense
//!
//! eBPF-based packet filtering at 100M+ PPS directly in NIC driver.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use tracing::{info, warn, error};

/// XDP program manager for first-line DDoS defense
pub struct XdpManager {
    /// Interface to attach XDP programs
    interfaces: Vec<String>,
    /// Path to XDP programs
    program_path: String,
    /// Currently loaded blocklist
    blocklist: parking_lot::RwLock<HashMap<IpAddr, BlocklistEntry>>,
    /// Rate limit table
    rate_limits: parking_lot::RwLock<HashMap<IpAddr, RateLimitEntry>>,
}

#[derive(Debug, Clone)]
pub struct BlocklistEntry {
    pub ip: IpAddr,
    pub reason: BlockReason,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub packets_dropped: u64,
}

#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub ip: IpAddr,
    pub pps_limit: u64,
    pub bps_limit: u64,
    pub current_pps: u64,
    pub current_bps: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum BlockReason {
    DdosAttack,
    SynFlood,
    UdpFlood,
    Amplification,
    BotNetwork,
    Manual,
}

impl XdpManager {
    pub fn new(interfaces: Vec<String>) -> Self {
        Self {
            interfaces,
            program_path: "/opt/opensase/xdp".to_string(),
            blocklist: parking_lot::RwLock::new(HashMap::new()),
            rate_limits: parking_lot::RwLock::new(HashMap::new()),
        }
    }
    
    /// Load XDP program on all interfaces
    pub async fn load(&self) -> Result<(), String> {
        for iface in &self.interfaces {
            self.load_interface(iface).await?;
        }
        
        info!("XDP programs loaded on {} interfaces", self.interfaces.len());
        Ok(())
    }
    
    async fn load_interface(&self, interface: &str) -> Result<(), String> {
        use tokio::process::Command;
        
        let xdp_prog = format!("{}/ddos_filter.o", self.program_path);
        
        // Check if program exists
        if !Path::new(&xdp_prog).exists() {
            warn!("XDP program not found: {}", xdp_prog);
            return Ok(()); // Non-fatal
        }
        
        // Load using ip link
        let output = Command::new("ip")
            .args(["link", "set", "dev", interface, "xdp", "obj", &xdp_prog, "sec", "xdp_ddos"])
            .output()
            .await
            .map_err(|e| format!("Failed to load XDP: {}", e))?;
        
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            // Try native mode
            let output2 = Command::new("ip")
                .args(["link", "set", "dev", interface, "xdpgeneric", "obj", &xdp_prog, "sec", "xdp_ddos"])
                .output()
                .await
                .map_err(|e| format!("Failed to load XDP generic: {}", e))?;
            
            if !output2.status.success() {
                return Err(format!("XDP load failed: {}", err));
            }
            
            info!("XDP loaded in generic mode on {}", interface);
        } else {
            info!("XDP loaded in native mode on {}", interface);
        }
        
        Ok(())
    }
    
    /// Unload XDP program
    pub async fn unload(&self) -> Result<(), String> {
        use tokio::process::Command;
        
        for iface in &self.interfaces {
            let _ = Command::new("ip")
                .args(["link", "set", "dev", iface, "xdp", "off"])
                .output()
                .await;
        }
        
        info!("XDP programs unloaded");
        Ok(())
    }
    
    // =========================================================================
    // Blocklist Management
    // =========================================================================
    
    /// Add IP to XDP blocklist
    pub async fn block_ip(&self, ip: IpAddr, reason: BlockReason, ttl_seconds: Option<u64>) -> Result<(), String> {
        let entry = BlocklistEntry {
            ip,
            reason,
            added_at: chrono::Utc::now(),
            expires_at: ttl_seconds.map(|s| chrono::Utc::now() + chrono::Duration::seconds(s as i64)),
            packets_dropped: 0,
        };
        
        // Update BPF map via bpftool
        self.update_bpf_map("blocklist", &ip_to_key(ip), &[1u8]).await?;
        
        self.blocklist.write().insert(ip, entry);
        
        info!("Blocked {} via XDP: {:?}", ip, reason);
        Ok(())
    }
    
    /// Remove IP from blocklist
    pub async fn unblock_ip(&self, ip: IpAddr) -> Result<(), String> {
        self.delete_bpf_map("blocklist", &ip_to_key(ip)).await?;
        self.blocklist.write().remove(&ip);
        
        info!("Unblocked {} from XDP", ip);
        Ok(())
    }
    
    /// Add network (CIDR) to blocklist
    pub async fn block_network(&self, prefix: &str, reason: BlockReason) -> Result<(), String> {
        // Parse CIDR
        let network: ipnetwork::IpNetwork = prefix.parse()
            .map_err(|e| format!("Invalid CIDR: {}", e))?;
        
        // For /24 and larger, block in LPM trie
        self.update_bpf_lpm_map("blocklist_lpm", &network_to_key(&network), &[1u8]).await?;
        
        info!("Blocked network {} via XDP: {:?}", prefix, reason);
        Ok(())
    }
    
    // =========================================================================
    // Rate Limiting
    // =========================================================================
    
    /// Set rate limit for source IP
    pub async fn set_rate_limit(&self, ip: IpAddr, pps: u64, bps: u64) -> Result<(), String> {
        let entry = RateLimitEntry {
            ip,
            pps_limit: pps,
            bps_limit: bps,
            current_pps: 0,
            current_bps: 0,
        };
        
        // Encode rate limit: 8 bytes PPS + 8 bytes BPS
        let mut value = Vec::with_capacity(16);
        value.extend_from_slice(&pps.to_le_bytes());
        value.extend_from_slice(&bps.to_le_bytes());
        
        self.update_bpf_map("rate_limits", &ip_to_key(ip), &value).await?;
        self.rate_limits.write().insert(ip, entry);
        
        info!("XDP rate limit set for {}: {} pps, {} bps", ip, pps, bps);
        Ok(())
    }
    
    /// Remove rate limit
    pub async fn remove_rate_limit(&self, ip: IpAddr) -> Result<(), String> {
        self.delete_bpf_map("rate_limits", &ip_to_key(ip)).await?;
        self.rate_limits.write().remove(&ip);
        Ok(())
    }
    
    // =========================================================================
    // Statistics
    // =========================================================================
    
    /// Get XDP drop statistics
    pub async fn get_stats(&self) -> Result<XdpStats, String> {
        let output = self.read_bpf_map("xdp_stats").await?;
        
        // Parse stats from BPF map
        let mut stats = XdpStats::default();
        
        // Simplified parsing - real impl would parse BPF map format
        stats.packets_received = parse_stat(&output, "received").unwrap_or(0);
        stats.packets_dropped = parse_stat(&output, "dropped").unwrap_or(0);
        stats.packets_passed = parse_stat(&output, "passed").unwrap_or(0);
        stats.blocklist_hits = parse_stat(&output, "blocklist").unwrap_or(0);
        stats.rate_limit_hits = parse_stat(&output, "ratelimit").unwrap_or(0);
        
        Ok(stats)
    }
    
    /// Get per-CPU statistics
    pub async fn get_per_cpu_stats(&self) -> Result<Vec<XdpStats>, String> {
        // Would read from percpu BPF map
        Ok(vec![self.get_stats().await?])
    }
    
    // =========================================================================
    // BPF Map Helpers
    // =========================================================================
    
    async fn update_bpf_map(&self, map_name: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        use tokio::process::Command;
        
        let key_hex = hex::encode(key);
        let value_hex = hex::encode(value);
        
        let map_path = format!("/sys/fs/bpf/{}", map_name);
        
        let output = Command::new("bpftool")
            .args(["map", "update", "pinned", &map_path, "key", "hex", &key_hex, "value", "hex", &value_hex])
            .output()
            .await
            .map_err(|e| format!("bpftool failed: {}", e))?;
        
        if !output.status.success() {
            warn!("BPF map update failed: {:?}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    async fn delete_bpf_map(&self, map_name: &str, key: &[u8]) -> Result<(), String> {
        use tokio::process::Command;
        
        let key_hex = hex::encode(key);
        let map_path = format!("/sys/fs/bpf/{}", map_name);
        
        let _ = Command::new("bpftool")
            .args(["map", "delete", "pinned", &map_path, "key", "hex", &key_hex])
            .output()
            .await;
        
        Ok(())
    }
    
    async fn update_bpf_lpm_map(&self, map_name: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.update_bpf_map(map_name, key, value).await
    }
    
    async fn read_bpf_map(&self, map_name: &str) -> Result<String, String> {
        use tokio::process::Command;
        
        let map_path = format!("/sys/fs/bpf/{}", map_name);
        
        let output = Command::new("bpftool")
            .args(["map", "dump", "pinned", &map_path])
            .output()
            .await
            .map_err(|e| format!("bpftool dump failed: {}", e))?;
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[derive(Debug, Default, Clone)]
pub struct XdpStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub bytes_received: u64,
    pub bytes_dropped: u64,
    pub blocklist_hits: u64,
    pub rate_limit_hits: u64,
    pub syn_cookies_sent: u64,
}

fn ip_to_key(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn network_to_key(network: &ipnetwork::IpNetwork) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(network.prefix()); // Prefix length first for LPM
    match network.ip() {
        IpAddr::V4(v4) => key.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => key.extend_from_slice(&v6.octets()),
    }
    key
}

fn parse_stat(output: &str, key: &str) -> Option<u64> {
    output.lines()
        .find(|l| l.contains(key))
        .and_then(|l| l.split_whitespace().last())
        .and_then(|s| s.parse().ok())
}
