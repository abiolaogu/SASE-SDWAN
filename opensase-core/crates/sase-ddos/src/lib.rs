//! OpenSASE DDoS Shield (ODDS)
//!
//! Carrier-grade DDoS mitigation system for 100+ Gbps attacks.
//! Operates at line-rate within the VPP data plane.
//!
//! # Performance Targets
//! - Absorb 100+ Gbps volumetric attacks
//! - Mitigate 50M+ PPS SYN floods
//! - <100μs detection latency
//! - <1ms mitigation activation
//! - Zero false positives

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod classifier;
pub mod detector;
pub mod mitigator;
pub mod flowspec;
pub mod baseline;
pub mod vpp;
pub mod xdp;
pub mod app_layer;
pub mod scrubbing;
pub mod ml_detection;
pub mod dashboard;

// =============================================================================
// Attack Types
// =============================================================================

/// Categories of DDoS attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    // Volumetric attacks
    UdpFlood,
    IcmpFlood,
    DnsAmplification,
    NtpAmplification,
    SsdpAmplification,
    MemcachedAmplification,
    ChargenAmplification,
    
    // Protocol attacks
    SynFlood,
    AckFlood,
    RstFlood,
    FragmentFlood,
    
    // Application layer
    HttpFlood,
    SlowLoris,
    DnsQueryFlood,
    
    // Mixed/Unknown
    MultiVector,
    Unknown,
}

impl AttackType {
    /// Get severity multiplier for prioritization
    pub fn severity(&self) -> u8 {
        match self {
            Self::SynFlood => 10,
            Self::MemcachedAmplification => 10,
            Self::DnsAmplification => 9,
            Self::NtpAmplification => 9,
            Self::HttpFlood => 8,
            Self::UdpFlood => 7,
            Self::MultiVector => 10,
            _ => 5,
        }
    }
    
    /// Get recommended mitigation strategy
    pub fn mitigation_strategy(&self) -> MitigationStrategy {
        match self {
            Self::SynFlood => MitigationStrategy::SynCookie,
            Self::UdpFlood | Self::IcmpFlood => MitigationStrategy::RateLimit,
            Self::DnsAmplification | Self::NtpAmplification => MitigationStrategy::SourceBlock,
            Self::MemcachedAmplification => MitigationStrategy::PortBlock,
            Self::HttpFlood => MitigationStrategy::ChallengePage,
            Self::SlowLoris => MitigationStrategy::ConnectionLimit,
            _ => MitigationStrategy::RateLimit,
        }
    }
}

// =============================================================================
// Mitigation Strategies
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitigationStrategy {
    /// SYN cookies for TCP handshake protection
    SynCookie,
    /// SYN proxy with connection tracking
    SynProxy,
    /// Rate limiting by source/destination
    RateLimit,
    /// Block specific source IPs/networks
    SourceBlock,
    /// Block specific ports
    PortBlock,
    /// Geographic blocking
    GeoBlock,
    /// Challenge-response (CAPTCHA/JS)
    ChallengePage,
    /// Connection rate limiting
    ConnectionLimit,
    /// BGP Flowspec to upstream
    BgpFlowspec,
    /// Remote Triggered Black Hole
    Rtbh,
    /// Divert to scrubbing center
    Scrubbing,
    /// Allow (whitelist)
    Allow,
}

// =============================================================================
// Attack Detection
// =============================================================================

/// Represents a detected attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attack {
    pub id: String,
    pub attack_type: AttackType,
    pub target: AttackTarget,
    pub sources: Vec<AttackSource>,
    pub metrics: AttackMetrics,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub status: AttackStatus,
    pub mitigation: Option<ActiveMitigation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTarget {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub protocol: Protocol,
    pub customer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSource {
    pub ip: IpAddr,
    pub network: Option<String>,  // CIDR
    pub asn: Option<u32>,
    pub country: Option<String>,
    pub pps: u64,
    pub bps: u64,
    pub is_spoofed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMetrics {
    pub total_pps: u64,
    pub total_bps: u64,
    pub peak_pps: u64,
    pub peak_bps: u64,
    pub unique_sources: u64,
    pub avg_packet_size: u32,
    pub protocol_distribution: HashMap<Protocol, f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackStatus {
    Detected,
    Analyzing,
    Mitigating,
    Mitigated,
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Gre,
    Other(u8),
}

// =============================================================================
// Active Mitigation
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveMitigation {
    pub id: String,
    pub strategy: MitigationStrategy,
    pub rules: Vec<MitigationRule>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub stats: MitigationStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationRule {
    pub rule_type: RuleType,
    pub source: Option<IpAddr>,
    pub source_prefix: Option<String>,
    pub destination: Option<IpAddr>,
    pub protocol: Option<Protocol>,
    pub port: Option<u16>,
    pub action: RuleAction,
    pub rate_limit: Option<RateLimit>,
    pub priority: u32,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    VppAcl,
    VppPolicer,
    BirdRtbh,
    BgpFlowspec,
    IptablesRate,
    SynCookie,
    SynProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Drop,
    RateLimit,
    Mark,
    Redirect,
    Allow,
    SynCookie,
    Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub pps: Option<u64>,
    pub bps: Option<u64>,
    pub burst: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitigationStats {
    pub packets_dropped: u64,
    pub bytes_dropped: u64,
    pub packets_allowed: u64,
    pub bytes_allowed: u64,
    pub syn_cookies_sent: u64,
    pub challenges_issued: u64,
}

// =============================================================================
// Traffic Baseline
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficBaseline {
    pub target: IpAddr,
    pub normal_pps: u64,
    pub normal_bps: u64,
    pub normal_connections_per_sec: u64,
    pub protocol_distribution: HashMap<Protocol, f64>,
    pub port_distribution: HashMap<u16, f64>,
    pub geo_distribution: HashMap<String, f64>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl TrafficBaseline {
    /// Check if current traffic deviates from baseline
    pub fn is_anomaly(&self, current_pps: u64, current_bps: u64, threshold: f64) -> bool {
        let pps_ratio = current_pps as f64 / self.normal_pps.max(1) as f64;
        let bps_ratio = current_bps as f64 / self.normal_bps.max(1) as f64;
        
        pps_ratio > threshold || bps_ratio > threshold
    }
}

// =============================================================================
// Detection Thresholds
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Multiplier above baseline to trigger detection
    pub anomaly_threshold: f64,
    /// Minimum PPS to consider as attack
    pub min_pps_threshold: u64,
    /// Minimum BPS to consider as attack
    pub min_bps_threshold: u64,
    /// SYN ratio threshold (SYN/ACK ratio)
    pub syn_ratio_threshold: f64,
    /// Entropy threshold for source IP distribution
    pub entropy_threshold: f64,
    /// Detection window in milliseconds
    pub detection_window_ms: u64,
    /// Cooldown before re-detecting same attack
    pub cooldown_seconds: u64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 3.0,      // 3x normal traffic
            min_pps_threshold: 100_000,  // 100K PPS
            min_bps_threshold: 100_000_000, // 100 Mbps
            syn_ratio_threshold: 0.8,    // 80% SYN packets
            entropy_threshold: 2.0,      // Low entropy = attack
            detection_window_ms: 100,    // 100ms window
            cooldown_seconds: 300,       // 5 minute cooldown
        }
    }
}

// =============================================================================
// DDoS Shield Service
// =============================================================================

/// Main DDoS Shield service
pub struct DdosShield {
    config: DetectionConfig,
    baselines: HashMap<IpAddr, TrafficBaseline>,
    active_attacks: HashMap<String, Attack>,
    active_mitigations: HashMap<String, ActiveMitigation>,
    detector: Arc<detector::AttackDetector>,
    mitigator: Arc<mitigator::MitigationEngine>,
}

impl DdosShield {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config: config.clone(),
            baselines: HashMap::new(),
            active_attacks: HashMap::new(),
            active_mitigations: HashMap::new(),
            detector: Arc::new(detector::AttackDetector::new(config.clone())),
            mitigator: Arc::new(mitigator::MitigationEngine::new()),
        }
    }
    
    /// Process incoming traffic sample
    pub async fn process_sample(&mut self, sample: &TrafficSample) -> Option<Attack> {
        // Check against baseline
        let baseline = self.baselines.get(&sample.destination);
        
        // Detect anomalies
        if let Some(attack) = self.detector.analyze(sample, baseline).await {
            // Classify attack type
            let classified = classifier::classify(&attack);
            
            // Auto-mitigate if enabled
            if classified.attack_type.severity() >= 7 {
                let mitigation = self.mitigator.activate(&classified).await;
                self.active_mitigations.insert(mitigation.id.clone(), mitigation);
            }
            
            self.active_attacks.insert(classified.id.clone(), classified.clone());
            return Some(classified);
        }
        
        None
    }
    
    /// Get currently active attacks
    pub fn active_attacks(&self) -> Vec<&Attack> {
        self.active_attacks.values().collect()
    }
    
    /// Manually trigger mitigation
    pub async fn mitigate(&mut self, attack_id: &str, strategy: MitigationStrategy) -> Result<ActiveMitigation, String> {
        let attack = self.active_attacks.get(attack_id)
            .ok_or_else(|| "Attack not found".to_string())?;
        
        let mitigation = self.mitigator.activate_with_strategy(attack, strategy).await;
        self.active_mitigations.insert(mitigation.id.clone(), mitigation.clone());
        
        Ok(mitigation)
    }
    
    /// Stop mitigation
    pub async fn stop_mitigation(&mut self, mitigation_id: &str) -> Result<(), String> {
        if let Some(mitigation) = self.active_mitigations.remove(mitigation_id) {
            self.mitigator.deactivate(&mitigation).await;
        }
        Ok(())
    }
}

/// Traffic sample from VPP/DPDK
#[derive(Debug, Clone)]
pub struct TrafficSample {
    pub timestamp: Instant,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_size: u32,
    pub tcp_flags: Option<u8>,
    pub pps: u64,
    pub bps: u64,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_attack_type_severity() {
        assert_eq!(AttackType::SynFlood.severity(), 10);
        assert_eq!(AttackType::UdpFlood.severity(), 7);
    }
    
    #[test]
    fn test_baseline_anomaly() {
        let baseline = TrafficBaseline {
            target: "10.0.0.1".parse().unwrap(),
            normal_pps: 10000,
            normal_bps: 100_000_000,
            normal_connections_per_sec: 1000,
            protocol_distribution: HashMap::new(),
            port_distribution: HashMap::new(),
            geo_distribution: HashMap::new(),
            updated_at: chrono::Utc::now(),
        };
        
        // Normal traffic - no anomaly
        assert!(!baseline.is_anomaly(15000, 150_000_000, 3.0));
        
        // Attack - anomaly detected
        assert!(baseline.is_anomaly(100000, 1_000_000_000, 3.0));
    }
}
