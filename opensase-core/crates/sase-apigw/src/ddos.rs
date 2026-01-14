//! DDoS Protection for APIs
//!
//! Protect APIs from DDoS attacks with various detection and mitigation strategies.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// DDoS protection manager
pub struct DdosProtection {
    config: DdosConfig,
    ip_tracker: parking_lot::RwLock<HashMap<String, IpStats>>,
    global_stats: GlobalStats,
    blocked_ips: parking_lot::RwLock<HashMap<String, Instant>>,
    fingerprint_tracker: parking_lot::RwLock<HashMap<String, u64>>,
}

/// DDoS protection configuration
#[derive(Clone, Debug)]
pub struct DdosConfig {
    /// Max requests per IP per second
    pub max_rps_per_ip: u32,
    /// Max requests per IP per minute
    pub max_rpm_per_ip: u32,
    /// Max concurrent connections per IP
    pub max_connections_per_ip: u32,
    /// Global request rate threshold (trigger level)
    pub global_rps_threshold: u32,
    /// Block duration in seconds
    pub block_duration_secs: u64,
    /// Enable fingerprinting
    pub enable_fingerprinting: bool,
    /// Enable geographic blocking
    pub enable_geo_blocking: bool,
    /// Blocked countries
    pub blocked_countries: Vec<String>,
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            max_rps_per_ip: 100,
            max_rpm_per_ip: 1000,
            max_connections_per_ip: 50,
            global_rps_threshold: 10000,
            block_duration_secs: 300,
            enable_fingerprinting: true,
            enable_geo_blocking: false,
            blocked_countries: Vec::new(),
        }
    }
}

/// Per-IP statistics
struct IpStats {
    requests: Vec<Instant>,
    connections: AtomicU64,
    first_seen: Instant,
    violations: u32,
}

impl IpStats {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            connections: AtomicU64::new(0),
            first_seen: Instant::now(),
            violations: 0,
        }
    }
    
    fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.requests.retain(|&t| t > cutoff);
    }
    
    fn rps(&self) -> u32 {
        let cutoff = Instant::now() - Duration::from_secs(1);
        self.requests.iter().filter(|&&t| t > cutoff).count() as u32
    }
    
    fn rpm(&self) -> u32 {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.requests.iter().filter(|&&t| t > cutoff).count() as u32
    }
}

/// Global statistics
struct GlobalStats {
    total_requests: AtomicU64,
    requests_last_second: parking_lot::RwLock<Vec<Instant>>,
    blocked_requests: AtomicU64,
    active_connections: AtomicU64,
}

impl GlobalStats {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            requests_last_second: parking_lot::RwLock::new(Vec::new()),
            blocked_requests: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }
    
    fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.requests_last_second.write().push(Instant::now());
    }
    
    fn current_rps(&self) -> u32 {
        let mut requests = self.requests_last_second.write();
        let cutoff = Instant::now() - Duration::from_secs(1);
        requests.retain(|&t| t > cutoff);
        requests.len() as u32
    }
}

/// DDoS detection result
#[derive(Clone, Debug)]
pub struct DdosCheckResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub block_until: Option<Instant>,
    pub threat_level: ThreatLevel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl DdosProtection {
    /// Create new DDoS protection
    pub fn new(config: DdosConfig) -> Self {
        Self {
            config,
            ip_tracker: parking_lot::RwLock::new(HashMap::new()),
            global_stats: GlobalStats::new(),
            blocked_ips: parking_lot::RwLock::new(HashMap::new()),
            fingerprint_tracker: parking_lot::RwLock::new(HashMap::new()),
        }
    }
    
    /// Check if request should be allowed
    pub fn check(&self, request: &DdosRequest) -> DdosCheckResult {
        // Check if IP is blocked
        if let Some(block_until) = self.is_blocked(&request.client_ip) {
            return DdosCheckResult {
                allowed: false,
                reason: Some("IP temporarily blocked".to_string()),
                block_until: Some(block_until),
                threat_level: ThreatLevel::High,
            };
        }
        
        // Check geographic restrictions
        if self.config.enable_geo_blocking {
            if let Some(country) = &request.country_code {
                if self.config.blocked_countries.contains(country) {
                    return DdosCheckResult {
                        allowed: false,
                        reason: Some("Geographic restriction".to_string()),
                        block_until: None,
                        threat_level: ThreatLevel::Medium,
                    };
                }
            }
        }
        
        // Record request and check limits
        self.global_stats.record_request();
        
        let threat_level = self.assess_threat(&request.client_ip);
        
        // Check per-IP limits
        let mut ip_tracker = self.ip_tracker.write();
        let stats = ip_tracker.entry(request.client_ip.clone())
            .or_insert_with(IpStats::new);
        
        stats.requests.push(Instant::now());
        stats.cleanup();
        
        let rps = stats.rps();
        let rpm = stats.rpm();
        
        // Check rate limits
        if rps > self.config.max_rps_per_ip {
            stats.violations += 1;
            
            if stats.violations >= 3 {
                drop(ip_tracker);
                self.block_ip(&request.client_ip);
                return DdosCheckResult {
                    allowed: false,
                    reason: Some("Rate limit exceeded - IP blocked".to_string()),
                    block_until: Some(Instant::now() + Duration::from_secs(self.config.block_duration_secs)),
                    threat_level: ThreatLevel::High,
                };
            }
            
            return DdosCheckResult {
                allowed: false,
                reason: Some("Rate limit exceeded".to_string()),
                block_until: None,
                threat_level: ThreatLevel::Medium,
            };
        }
        
        if rpm > self.config.max_rpm_per_ip {
            return DdosCheckResult {
                allowed: false,
                reason: Some("Minute rate limit exceeded".to_string()),
                block_until: None,
                threat_level: ThreatLevel::Medium,
            };
        }
        
        // Check fingerprinting
        if self.config.enable_fingerprinting {
            if let Some(fingerprint) = &request.fingerprint {
                let mut tracker = self.fingerprint_tracker.write();
                let count = tracker.entry(fingerprint.clone()).or_insert(0);
                *count += 1;
                
                if *count > 1000 {
                    return DdosCheckResult {
                        allowed: false,
                        reason: Some("Suspicious traffic pattern".to_string()),
                        block_until: None,
                        threat_level: ThreatLevel::High,
                    };
                }
            }
        }
        
        // Check global threshold
        let global_rps = self.global_stats.current_rps();
        if global_rps > self.config.global_rps_threshold {
            // Under attack - apply stricter limits
            if rps > self.config.max_rps_per_ip / 2 {
                return DdosCheckResult {
                    allowed: false,
                    reason: Some("Under attack - stricter limits applied".to_string()),
                    block_until: None,
                    threat_level: ThreatLevel::Critical,
                };
            }
        }
        
        DdosCheckResult {
            allowed: true,
            reason: None,
            block_until: None,
            threat_level,
        }
    }
    
    /// Block an IP address
    pub fn block_ip(&self, ip: &str) {
        let block_until = Instant::now() + Duration::from_secs(self.config.block_duration_secs);
        self.blocked_ips.write().insert(ip.to_string(), block_until);
        self.global_stats.blocked_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Unblock an IP address
    pub fn unblock_ip(&self, ip: &str) {
        self.blocked_ips.write().remove(ip);
    }
    
    /// Check if IP is blocked
    pub fn is_blocked(&self, ip: &str) -> Option<Instant> {
        let blocked = self.blocked_ips.read();
        if let Some(&block_until) = blocked.get(ip) {
            if Instant::now() < block_until {
                return Some(block_until);
            }
        }
        None
    }
    
    /// Assess threat level for an IP
    fn assess_threat(&self, ip: &str) -> ThreatLevel {
        let tracker = self.ip_tracker.read();
        
        if let Some(stats) = tracker.get(ip) {
            let rps = stats.rps();
            let violations = stats.violations;
            
            if violations >= 3 || rps > self.config.max_rps_per_ip * 2 {
                return ThreatLevel::Critical;
            } else if violations >= 2 || rps > self.config.max_rps_per_ip {
                return ThreatLevel::High;
            } else if violations >= 1 || rps > self.config.max_rps_per_ip / 2 {
                return ThreatLevel::Medium;
            } else if rps > self.config.max_rps_per_ip / 4 {
                return ThreatLevel::Low;
            }
        }
        
        ThreatLevel::None
    }
    
    /// Get protection statistics
    pub fn get_stats(&self) -> DdosStats {
        DdosStats {
            total_requests: self.global_stats.total_requests.load(Ordering::Relaxed),
            blocked_requests: self.global_stats.blocked_requests.load(Ordering::Relaxed),
            blocked_ips: self.blocked_ips.read().len(),
            current_rps: self.global_stats.current_rps(),
            active_connections: self.global_stats.active_connections.load(Ordering::Relaxed),
            under_attack: self.global_stats.current_rps() > self.config.global_rps_threshold,
        }
    }
    
    /// Cleanup stale entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        
        // Remove expired blocks
        self.blocked_ips.write().retain(|_, &mut block_until| now < block_until);
        
        // Cleanup IP tracker
        let cutoff = now - Duration::from_secs(300);
        self.ip_tracker.write().retain(|_, stats| stats.first_seen > cutoff);
        
        // Cleanup fingerprints
        self.fingerprint_tracker.write().clear();
    }
}

/// DDoS request information
#[derive(Clone, Debug)]
pub struct DdosRequest {
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub path: String,
    pub method: String,
    pub country_code: Option<String>,
    pub fingerprint: Option<String>,
}

impl DdosRequest {
    pub fn new(client_ip: &str, path: &str, method: &str) -> Self {
        Self {
            client_ip: client_ip.to_string(),
            user_agent: None,
            path: path.to_string(),
            method: method.to_string(),
            country_code: None,
            fingerprint: None,
        }
    }
    
    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_string());
        self
    }
    
    pub fn with_country(mut self, country: &str) -> Self {
        self.country_code = Some(country.to_string());
        self
    }
    
    pub fn with_fingerprint(mut self, fp: &str) -> Self {
        self.fingerprint = Some(fp.to_string());
        self
    }
}

/// DDoS protection statistics
#[derive(Clone, Debug)]
pub struct DdosStats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub blocked_ips: usize,
    pub current_rps: u32,
    pub active_connections: u64,
    pub under_attack: bool,
}
