//! Blocklist Manager - Domain blocklist with bloom filter

use bloomfilter::Bloom;
use dashmap::DashMap;
use std::sync::RwLock;
use tracing::{info, debug};

/// Blocklist manager
pub struct BlocklistManager {
    /// Bloom filter for fast negative lookup (~1MB for 1M domains)
    bloom: RwLock<Bloom<String>>,
    
    /// Exact blocklist with reasons
    blocklist: DashMap<String, String>,
    
    /// Domain count
    count: std::sync::atomic::AtomicUsize,
}

impl BlocklistManager {
    /// Create new blocklist manager
    pub fn new() -> Self {
        // Bloom filter for ~1M items with 0.1% false positive rate
        let bloom = Bloom::new_for_fp_rate(1_000_000, 0.001);
        
        Self {
            bloom: RwLock::new(bloom),
            blocklist: DashMap::new(),
            count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    
    /// Check if domain is probably blocked (may have false positives)
    pub fn probably_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        let bloom = self.bloom.read().unwrap();
        bloom.check(&domain_lower)
    }
    
    /// Check if domain is exactly blocked
    pub async fn is_blocked_exact(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();
        
        // Direct lookup
        if let Some(reason) = self.blocklist.get(&domain_lower) {
            return Some(reason.clone());
        }
        
        // Check parent domains
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if let Some(reason) = self.blocklist.get(&parent) {
                return Some(reason.clone());
            }
        }
        
        None
    }
    
    /// Add domain to blocklist
    pub fn add(&self, domain: &str, reason: &str) {
        let domain_lower = domain.to_lowercase();
        
        // Add to bloom filter
        {
            let mut bloom = self.bloom.write().unwrap();
            bloom.set(&domain_lower);
        }
        
        // Add to exact list
        self.blocklist.insert(domain_lower, reason.to_string());
        self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    /// Remove domain from blocklist
    pub fn remove(&self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        
        // Can only remove from exact list (bloom filter doesn't support removal)
        if self.blocklist.remove(&domain_lower).is_some() {
            self.count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    
    /// Get count
    pub fn count(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    /// Load from blocklist sources
    pub async fn load_from_sources(&self) {
        let sources = vec![
            ("malware", include_str!("../../../data/blocklists/malware.txt").lines()),
            ("phishing", include_str!("../../../data/blocklists/phishing.txt").lines()),
        ];
        
        // Note: In production, would fetch from URLs
        // For now, use inline defaults
        self.load_defaults();
    }
    
    /// Load default blocklist
    pub fn load_defaults(&self) {
        // Malware domains
        let malware_domains = [
            "malware.com", "evil.com", "badsite.net", "exploit.io",
            "trojan.xyz", "ransomware.me", "keylogger.biz",
        ];
        
        for domain in malware_domains {
            self.add(domain, "Known malware distribution site");
        }
        
        // Phishing domains
        let phishing_domains = [
            "login-facebook-secure.com", "paypal-verify.net",
            "amazon-security-update.com", "google-signin-verify.net",
            "microsoft-account-alert.com", "apple-id-verify.org",
        ];
        
        for domain in phishing_domains {
            self.add(domain, "Known phishing site");
        }
        
        // C2 domains
        let c2_domains = [
            "c2-server.xyz", "botnet-command.net",
        ];
        
        for domain in c2_domains {
            self.add(domain, "Command and control server");
        }
        
        info!("Loaded {} blocked domains", self.count());
    }
}

impl Default for BlocklistManager {
    fn default() -> Self {
        Self::new()
    }
}
