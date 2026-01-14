//! VPP Scrubbing Engine
//!
//! Advanced DDoS scrubbing with SYN proxy and flow tracking.

use crate::{Attack, AttackType, Protocol, MitigationStrategy};
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use dashmap::DashMap;

/// VPP-integrated scrubbing engine for 100 Gbps throughput
pub struct ScrubbingEngine {
    /// SYN proxy for stateless cookie validation
    syn_proxy: SynProxy,
    /// Flow tracker for connection state
    flow_tracker: FlowTracker,
    /// Per-source rate limiters
    rate_limiters: DashMap<IpAddr, RateLimiter>,
    /// Active attack status per destination
    attack_status: DashMap<IpAddr, AttackStatus>,
    /// Scrubbing statistics
    stats: ScrubbingStats,
}

#[derive(Debug, Clone)]
pub struct AttackStatus {
    pub under_attack: bool,
    pub attack_type: AttackType,
    pub target: IpAddr,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub peak_pps: u64,
    pub peak_bps: u64,
}

/// Packet representation for scrubbing
#[derive(Debug, Clone)]
pub struct Packet {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: Option<u8>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub payload_len: usize,
}

impl Packet {
    pub fn is_tcp_syn(&self) -> bool {
        self.tcp_flags.map(|f| f & 0x02 != 0 && f & 0x10 == 0).unwrap_or(false)
    }
    
    pub fn is_tcp_ack(&self) -> bool {
        self.tcp_flags.map(|f| f & 0x10 != 0).unwrap_or(false)
    }
    
    pub fn is_tcp_syn_ack(&self) -> bool {
        self.tcp_flags.map(|f| f & 0x12 == 0x12).unwrap_or(false)
    }
    
    pub fn flow_key(&self) -> FlowKey {
        FlowKey {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            protocol: self.protocol,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

/// Scrubbing result
#[derive(Debug, Clone)]
pub enum ScrubResult {
    /// Allow packet through
    Pass,
    /// Drop packet with reason
    Drop(DropReason),
    /// Respond with packet (e.g., SYN-ACK)
    Respond(Vec<u8>),
    /// Challenge client
    Challenge(ChallengeType),
    /// Pass with additional action
    PassWithAction(ScrubAction),
}

#[derive(Debug, Clone, Copy)]
pub enum DropReason {
    Blocklisted,
    RateLimited,
    InvalidSynCookie,
    UnsolicitedResponse,
    ProtocolViolation,
    SuspiciousBehavior,
}

#[derive(Debug, Clone, Copy)]
pub enum ChallengeType {
    JavaScript,
    Captcha,
    Cookie,
}

#[derive(Debug, Clone)]
pub enum ScrubAction {
    CreateBackendConnection,
    MarkForInspection,
    LogForAnalysis,
}

impl ScrubbingEngine {
    pub fn new() -> Self {
        Self {
            syn_proxy: SynProxy::new(),
            flow_tracker: FlowTracker::new(),
            rate_limiters: DashMap::new(),
            attack_status: DashMap::new(),
            stats: ScrubbingStats::default(),
        }
    }
    
    /// Process packet through scrubbing pipeline
    pub async fn process_packet(&self, packet: &Packet) -> ScrubResult {
        self.stats.packets_processed.fetch_add(1, Ordering::Relaxed);
        
        // Check if destination is under attack
        let status = self.attack_status.get(&packet.dst_ip);
        
        if status.is_none() || !status.as_ref().map(|s| s.under_attack).unwrap_or(false) {
            // Normal operation - minimal processing
            return ScrubResult::Pass;
        }
        
        let attack_type = status.as_ref().map(|s| s.attack_type).unwrap_or(AttackType::Unknown);
        
        // Apply mitigation based on attack type
        match attack_type {
            AttackType::SynFlood => self.handle_syn_flood(packet).await,
            AttackType::UdpFlood | AttackType::DnsAmplification |
            AttackType::NtpAmplification | AttackType::MemcachedAmplification => {
                self.handle_amplification(packet).await
            }
            AttackType::HttpFlood => self.handle_http_flood(packet).await,
            _ => self.handle_generic(packet).await,
        }
    }
    
    /// SYN flood mitigation using SYN cookies
    async fn handle_syn_flood(&self, packet: &Packet) -> ScrubResult {
        if !packet.is_tcp_syn() && !packet.is_tcp_ack() {
            // Non-SYN/ACK TCP during SYN flood - rate limit
            return self.apply_rate_limit(packet);
        }
        
        if packet.is_tcp_syn() {
            // New SYN - respond with SYN-ACK containing cookie
            let cookie = self.syn_proxy.generate_cookie(packet);
            let syn_ack = self.syn_proxy.create_syn_ack(packet, cookie);
            
            self.stats.syn_cookies_sent.fetch_add(1, Ordering::Relaxed);
            return ScrubResult::Respond(syn_ack);
        }
        
        if packet.is_tcp_ack() {
            // Returning ACK - validate cookie
            if self.syn_proxy.validate_cookie(packet) {
                self.stats.syn_cookies_validated.fetch_add(1, Ordering::Relaxed);
                return ScrubResult::PassWithAction(ScrubAction::CreateBackendConnection);
            } else {
                self.stats.invalid_syn_cookies.fetch_add(1, Ordering::Relaxed);
                return ScrubResult::Drop(DropReason::InvalidSynCookie);
            }
        }
        
        ScrubResult::Pass
    }
    
    /// Amplification attack mitigation
    async fn handle_amplification(&self, packet: &Packet) -> ScrubResult {
        // Check for common amplification source ports
        const AMP_PORTS: [u16; 7] = [53, 123, 161, 389, 1900, 11211, 27015];
        
        if AMP_PORTS.contains(&packet.src_port) {
            // Check if we initiated this flow
            let reverse_key = FlowKey {
                src_ip: packet.dst_ip,
                dst_ip: packet.src_ip,
                src_port: packet.dst_port,
                dst_port: packet.src_port,
                protocol: packet.protocol,
            };
            
            if !self.flow_tracker.has_flow(&reverse_key) {
                self.stats.amp_responses_blocked.fetch_add(1, Ordering::Relaxed);
                return ScrubResult::Drop(DropReason::UnsolicitedResponse);
            }
        }
        
        self.apply_rate_limit(packet)
    }
    
    /// HTTP flood pre-filtering
    async fn handle_http_flood(&self, packet: &Packet) -> ScrubResult {
        // Check connection rate from source
        let conn_rate = self.flow_tracker.get_connection_rate(&packet.src_ip);
        
        if conn_rate > 100 {
            return ScrubResult::Challenge(ChallengeType::JavaScript);
        }
        
        if conn_rate > 50 {
            return ScrubResult::Challenge(ChallengeType::Captcha);
        }
        
        self.apply_rate_limit(packet)
    }
    
    /// Generic attack handling
    async fn handle_generic(&self, packet: &Packet) -> ScrubResult {
        self.apply_rate_limit(packet)
    }
    
    /// Apply per-source rate limiting
    fn apply_rate_limit(&self, packet: &Packet) -> ScrubResult {
        let limiter = self.rate_limiters
            .entry(packet.src_ip)
            .or_insert_with(|| RateLimiter::new(10000, 1000));
        
        if limiter.allow() {
            ScrubResult::Pass
        } else {
            self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
            ScrubResult::Drop(DropReason::RateLimited)
        }
    }
    
    /// Set attack status for destination
    pub fn set_attack_status(&self, attack: &Attack) {
        let status = AttackStatus {
            under_attack: true,
            attack_type: attack.attack_type,
            target: attack.target.ip,
            started_at: attack.started_at,
            peak_pps: attack.metrics.peak_pps,
            peak_bps: attack.metrics.peak_bps,
        };
        
        self.attack_status.insert(attack.target.ip, status);
    }
    
    /// Clear attack status
    pub fn clear_attack_status(&self, target: &IpAddr) {
        self.attack_status.remove(target);
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> ScrubbingSnapshot {
        ScrubbingSnapshot {
            packets_processed: self.stats.packets_processed.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            syn_cookies_sent: self.stats.syn_cookies_sent.load(Ordering::Relaxed),
            syn_cookies_validated: self.stats.syn_cookies_validated.load(Ordering::Relaxed),
            invalid_syn_cookies: self.stats.invalid_syn_cookies.load(Ordering::Relaxed),
            amp_responses_blocked: self.stats.amp_responses_blocked.load(Ordering::Relaxed),
            rate_limited: self.stats.rate_limited.load(Ordering::Relaxed),
        }
    }
}

impl Default for ScrubbingEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// SYN Proxy with stateless cookies
pub struct SynProxy {
    /// Secret for cookie generation
    secret: [u8; 32],
    /// MSS encoding table
    mss_table: [u16; 8],
}

impl SynProxy {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Generate secret from current time (should be from secure random in prod)
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let mut secret = [0u8; 32];
        for (i, b) in ts.to_le_bytes().iter().cycle().take(32).enumerate() {
            secret[i] = *b;
        }
        
        Self {
            secret,
            mss_table: [536, 1220, 1440, 1460, 4312, 8960, 9000, 65535],
        }
    }
    
    /// Generate SYN cookie for incoming SYN
    pub fn generate_cookie(&self, packet: &Packet) -> u32 {
        let timestamp = chrono::Utc::now().timestamp() / 60; // 1-minute granularity
        
        // Simple hash - production would use SipHash or similar
        let mut hash: u32 = 0;
        
        if let IpAddr::V4(v4) = packet.src_ip {
            hash ^= u32::from_be_bytes(v4.octets());
        }
        if let IpAddr::V4(v4) = packet.dst_ip {
            hash ^= u32::from_be_bytes(v4.octets());
        }
        hash ^= (packet.src_port as u32) << 16 | packet.dst_port as u32;
        hash ^= timestamp as u32;
        hash ^= u32::from_le_bytes([self.secret[0], self.secret[1], self.secret[2], self.secret[3]]);
        
        // Encode MSS in low 3 bits
        let mss_index = self.get_mss_index(1460); // Default MSS
        
        (hash & 0xFFFFFFF8) | mss_index
    }
    
    /// Validate returning ACK contains valid cookie
    pub fn validate_cookie(&self, packet: &Packet) -> bool {
        let ack = packet.tcp_ack.unwrap_or(0);
        let expected = self.generate_cookie(packet);
        
        // Check current minute
        if ack.wrapping_sub(1) == expected {
            return true;
        }
        
        // Check previous minute (clock skew tolerance)
        // Would regenerate with timestamp - 1
        
        false
    }
    
    /// Create SYN-ACK response with cookie
    pub fn create_syn_ack(&self, packet: &Packet, cookie: u32) -> Vec<u8> {
        // Would build actual TCP/IP packet
        // Simplified: return empty vec for now
        vec![]
    }
    
    fn get_mss_index(&self, mss: u16) -> u32 {
        for (i, &m) in self.mss_table.iter().enumerate() {
            if mss <= m {
                return i as u32;
            }
        }
        7
    }
}

impl Default for SynProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Flow tracker for connection state
pub struct FlowTracker {
    flows: DashMap<FlowKey, FlowState>,
    connection_rates: DashMap<IpAddr, ConnectionRate>,
}

#[derive(Debug, Clone)]
pub struct FlowState {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub packets: u64,
    pub bytes: u64,
}

struct ConnectionRate {
    count: AtomicU64,
    window_start: parking_lot::Mutex<chrono::DateTime<chrono::Utc>>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            flows: DashMap::new(),
            connection_rates: DashMap::new(),
        }
    }
    
    pub fn has_flow(&self, key: &FlowKey) -> bool {
        self.flows.contains_key(key)
    }
    
    pub fn add_flow(&self, key: FlowKey) {
        let now = chrono::Utc::now();
        self.flows.insert(key, FlowState {
            created_at: now,
            last_seen: now,
            packets: 1,
            bytes: 0,
        });
        
        // Update connection rate
        let rate = self.connection_rates
            .entry(key.src_ip)
            .or_insert_with(|| ConnectionRate {
                count: AtomicU64::new(0),
                window_start: parking_lot::Mutex::new(now),
            });
        
        {
            let mut window = rate.window_start.lock();
            if (now - *window).num_seconds() >= 1 {
                rate.count.store(0, Ordering::Relaxed);
                *window = now;
            }
        }
        rate.count.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_connection_rate(&self, ip: &IpAddr) -> u64 {
        self.connection_rates
            .get(ip)
            .map(|r| r.count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Token bucket rate limiter
pub struct RateLimiter {
    pps_limit: u64,
    burst: u64,
    tokens: AtomicU64,
    last_update: parking_lot::Mutex<std::time::Instant>,
}

impl RateLimiter {
    pub fn new(pps: u64, burst: u64) -> Self {
        Self {
            pps_limit: pps,
            burst,
            tokens: AtomicU64::new(burst),
            last_update: parking_lot::Mutex::new(std::time::Instant::now()),
        }
    }
    
    pub fn allow(&self) -> bool {
        let now = std::time::Instant::now();
        
        // Refill tokens
        {
            let mut last = self.last_update.lock();
            let elapsed = now.duration_since(*last).as_secs_f64();
            let refill = (elapsed * self.pps_limit as f64) as u64;
            
            if refill > 0 {
                let current = self.tokens.load(Ordering::Relaxed);
                let new_tokens = (current + refill).min(self.burst);
                self.tokens.store(new_tokens, Ordering::Relaxed);
                *last = now;
            }
        }
        
        // Try to consume token
        let current = self.tokens.load(Ordering::Relaxed);
        if current > 0 {
            self.tokens.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Default)]
struct ScrubbingStats {
    packets_processed: AtomicU64,
    packets_dropped: AtomicU64,
    syn_cookies_sent: AtomicU64,
    syn_cookies_validated: AtomicU64,
    invalid_syn_cookies: AtomicU64,
    amp_responses_blocked: AtomicU64,
    rate_limited: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct ScrubbingSnapshot {
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub syn_cookies_sent: u64,
    pub syn_cookies_validated: u64,
    pub invalid_syn_cookies: u64,
    pub amp_responses_blocked: u64,
    pub rate_limited: u64,
}
