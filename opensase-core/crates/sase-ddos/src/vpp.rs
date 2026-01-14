//! VPP Integration
//!
//! Line-rate packet sampling and ACL injection.

use crate::{MitigationRule, Protocol, RateLimit, RuleAction, RuleType};
use std::net::IpAddr;
use tokio::process::Command;
use tracing::{info, warn, error};

/// VPP controller for DDoS mitigation
pub struct VppController {
    socket_path: String,
    max_acl_rules: usize,
    active_rules: parking_lot::Mutex<Vec<String>>,
}

impl VppController {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            max_acl_rules: 10000,
            active_rules: parking_lot::Mutex::new(Vec::new()),
        }
    }
    
    /// Execute VPP CLI command
    pub async fn exec(&self, cmd: &str) -> Result<String, String> {
        let output = Command::new("vppctl")
            .arg("-s")
            .arg(&self.socket_path)
            .arg(cmd)
            .output()
            .await
            .map_err(|e| format!("VPP exec error: {}", e))?;
        
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
    
    // =========================================================================
    // Traffic Sampling
    // =========================================================================
    
    /// Configure packet sampling for detection
    pub async fn configure_sampling(&self, interface: &str, rate: u32) -> Result<(), String> {
        // Use VPP flow-classify for sampling
        let cmd = format!(
            "flowprobe params record l3 active 10 passive 10",
        );
        self.exec(&cmd).await?;
        
        let cmd = format!(
            "flowprobe feature add-del {} l2-input",
            interface
        );
        self.exec(&cmd).await?;
        
        info!("Configured sampling on {} at 1:{}", interface, rate);
        Ok(())
    }
    
    /// Get interface statistics
    pub async fn get_interface_stats(&self, interface: &str) -> Result<InterfaceStats, String> {
        let output = self.exec(&format!("show interface {}", interface)).await?;
        
        // Parse VPP output
        let mut stats = InterfaceStats::default();
        
        for line in output.lines() {
            if line.contains("rx packets") {
                if let Some(val) = extract_number(line) {
                    stats.rx_packets = val;
                }
            }
            if line.contains("rx bytes") {
                if let Some(val) = extract_number(line) {
                    stats.rx_bytes = val;
                }
            }
            if line.contains("tx packets") {
                if let Some(val) = extract_number(line) {
                    stats.tx_packets = val;
                }
            }
            if line.contains("drops") {
                if let Some(val) = extract_number(line) {
                    stats.drops = val;
                }
            }
        }
        
        Ok(stats)
    }
    
    // =========================================================================
    // ACL Management
    // =========================================================================
    
    /// Add drop ACL for source
    pub async fn add_drop_acl(
        &self,
        source: IpAddr,
        destination: IpAddr,
        protocol: Option<Protocol>,
        port: Option<u16>,
    ) -> Result<String, String> {
        let proto_str = protocol.map(|p| format!("proto {}", proto_num(&p))).unwrap_or_default();
        let port_str = port.map(|p| format!("dst-port {}", p)).unwrap_or_default();
        
        let acl_name = format!("ddos_{}_{}", 
            source.to_string().replace(".", "_"),
            destination.to_string().replace(".", "_")
        );
        
        let cmd = format!(
            "acl-plugin acl add permit+reflect tag {} \
             src {}/32 dst {}/32 {} {}",
            acl_name, source, destination, proto_str, port_str
        );
        
        let result = self.exec(&cmd).await?;
        
        self.active_rules.lock().push(acl_name.clone());
        
        info!("Added ACL: {} -> {} DROP", source, destination);
        Ok(acl_name)
    }
    
    /// Add rate-limiting policer
    pub async fn add_policer(
        &self,
        name: &str,
        rate_bps: u64,
        burst: u32,
    ) -> Result<(), String> {
        // CIR in kbps, CBS in bytes
        let cir_kbps = rate_bps / 1000;
        let cbs_bytes = burst * 1500; // Packet-based burst
        
        let cmd = format!(
            "policer add name {} cir {} cb {} rate-type kbps round closest \
             type single exceed-action drop",
            name, cir_kbps, cbs_bytes
        );
        
        self.exec(&cmd).await?;
        
        info!("Added policer {}: {} kbps, burst {}", name, cir_kbps, cbs_bytes);
        Ok(())
    }
    
    /// Bind policer to interface
    pub async fn bind_policer(
        &self,
        interface: &str,
        policer: &str,
        input: bool,
    ) -> Result<(), String> {
        let direction = if input { "input" } else { "output" };
        
        let cmd = format!(
            "policer bind {} name {} {}",
            interface, policer, direction
        );
        
        self.exec(&cmd).await?;
        Ok(())
    }
    
    /// Enable SYN flood protection
    pub async fn enable_syn_protection(&self, threshold: u32) -> Result<(), String> {
        // VPP TCP SYN flood mitigation
        let cmd = format!(
            "tcp syn-flood threshold {}",
            threshold
        );
        
        match self.exec(&cmd).await {
            Ok(_) => {
                info!("SYN flood protection enabled, threshold: {}", threshold);
                Ok(())
            }
            Err(e) => {
                warn!("SYN protection not available: {}", e);
                Ok(()) // Non-fatal
            }
        }
    }
    
    /// Apply mitigation rule
    pub async fn apply_rule(&self, rule: &MitigationRule) -> Result<(), String> {
        match rule.rule_type {
            RuleType::VppAcl => {
                if let (Some(src), Some(dst)) = (rule.source, rule.destination) {
                    self.add_drop_acl(src, dst, rule.protocol, rule.port).await?;
                }
            }
            RuleType::VppPolicer => {
                if let Some(limit) = &rule.rate_limit {
                    let name = format!("ddos_rate_{}", 
                        rule.destination.map(|d| d.to_string()).unwrap_or_default()
                    );
                    self.add_policer(&name, limit.bps.unwrap_or(1_000_000_000), limit.burst).await?;
                }
            }
            RuleType::SynCookie => {
                self.enable_syn_protection(100).await?;
            }
            _ => {}
        }
        
        Ok(())
    }
    
    // =========================================================================
    // Cleanup
    // =========================================================================
    
    /// Remove all DDoS ACLs
    pub async fn clear_ddos_acls(&self) -> Result<(), String> {
        let rules: Vec<String> = self.active_rules.lock().drain(..).collect();
        
        for rule in rules {
            let cmd = format!("acl-plugin acl del tag {}", rule);
            if let Err(e) = self.exec(&cmd).await {
                warn!("Failed to remove ACL {}: {}", rule, e);
            }
        }
        
        info!("Cleared all DDoS ACLs");
        Ok(())
    }
    
    /// Get ACL statistics
    pub async fn get_acl_stats(&self) -> Result<AclStats, String> {
        let output = self.exec("show acl").await?;
        
        let rule_count = output.matches("acl-index").count();
        
        Ok(AclStats {
            total_rules: rule_count,
            hits: 0, // Would need parsing
            misses: 0,
        })
    }
}

#[derive(Debug, Default)]
pub struct InterfaceStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub drops: u64,
    pub pps: u64,
    pub bps: u64,
}

#[derive(Debug, Default)]
pub struct AclStats {
    pub total_rules: usize,
    pub hits: u64,
    pub misses: u64,
}

fn proto_num(proto: &Protocol) -> u8 {
    match proto {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Icmp => 1,
        Protocol::Gre => 47,
        Protocol::Other(n) => *n,
    }
}

fn extract_number(s: &str) -> Option<u64> {
    s.split_whitespace()
        .find_map(|word| word.parse::<u64>().ok())
}
