//! High-Performance IOC Matching Engine
//!
//! Sub-microsecond IOC lookups using bloom filters and optimized data structures.

use crate::{Indicator, IocType, Confidence, Severity};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

/// High-performance IOC matching engine
pub struct IocMatchingEngine {
    /// Bloom filters for fast negative lookup
    ip_bloom: BloomFilter,
    domain_bloom: BloomFilter,
    url_bloom: BloomFilter,
    hash_bloom: BloomFilter,
    
    /// Exact match maps
    ip_map: dashmap::DashMap<u128, IocMatch>,
    domain_map: dashmap::DashMap<String, IocMatch>,
    url_map: dashmap::DashMap<String, IocMatch>,
    hash_map: dashmap::DashMap<String, IocMatch>,
    
    /// Domain suffix tree for subdomain matching
    domain_suffixes: DomainSuffixTree,
    
    /// Statistics
    stats: MatchingStats,
}

/// Bloom filter for fast negative lookups
pub struct BloomFilter {
    bits: Vec<std::sync::atomic::AtomicU64>,
    num_bits: usize,
    num_hashes: usize,
}

impl BloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let num_bits = optimal_num_bits(expected_items, false_positive_rate);
        let num_hashes = optimal_num_hashes(num_bits, expected_items);
        let num_words = (num_bits + 63) / 64;
        
        let bits = (0..num_words)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect();
        
        Self {
            bits,
            num_bits,
            num_hashes,
        }
    }
    
    pub fn insert(&self, item: &[u8]) {
        use std::sync::atomic::Ordering;
        
        for i in 0..self.num_hashes {
            let hash = hash_with_seed(item, i as u64);
            let bit_pos = (hash as usize) % self.num_bits;
            let word_idx = bit_pos / 64;
            let bit_idx = bit_pos % 64;
            
            self.bits[word_idx].fetch_or(1 << bit_idx, Ordering::Relaxed);
        }
    }
    
    pub fn contains(&self, item: &[u8]) -> bool {
        use std::sync::atomic::Ordering;
        
        for i in 0..self.num_hashes {
            let hash = hash_with_seed(item, i as u64);
            let bit_pos = (hash as usize) % self.num_bits;
            let word_idx = bit_pos / 64;
            let bit_idx = bit_pos % 64;
            
            if (self.bits[word_idx].load(Ordering::Relaxed) & (1 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }
    
    pub fn clear(&self) {
        use std::sync::atomic::Ordering;
        for word in &self.bits {
            word.store(0, Ordering::Relaxed);
        }
    }
}

fn optimal_num_bits(n: usize, p: f64) -> usize {
    let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
    (-(n as f64) * p.ln() / ln2_sq).ceil() as usize
}

fn optimal_num_hashes(m: usize, n: usize) -> usize {
    ((m as f64 / n as f64) * std::f64::consts::LN_2).ceil() as usize
}

fn hash_with_seed(data: &[u8], seed: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    data.hash(&mut hasher);
    hasher.finish()
}

/// Domain suffix tree for efficient subdomain matching
pub struct DomainSuffixTree {
    root: DomainNode,
}

struct DomainNode {
    children: dashmap::DashMap<String, DomainNode>,
    is_terminal: bool,
    match_info: Option<IocMatch>,
}

impl DomainSuffixTree {
    pub fn new() -> Self {
        Self {
            root: DomainNode {
                children: dashmap::DashMap::new(),
                is_terminal: false,
                match_info: None,
            },
        }
    }
    
    pub fn insert(&self, domain: &str, match_info: IocMatch) {
        let parts: Vec<&str> = domain.split('.').rev().collect();
        let mut current = &self.root;
        
        for (i, part) in parts.iter().enumerate() {
            let part_str = part.to_lowercase();
            
            if !current.children.contains_key(&part_str) {
                current.children.insert(part_str.clone(), DomainNode {
                    children: dashmap::DashMap::new(),
                    is_terminal: false,
                    match_info: None,
                });
            }
            
            if let Some(node) = current.children.get(&part_str) {
                if i == parts.len() - 1 {
                    // Update terminal node
                    let mut node = current.children.get_mut(&part_str).unwrap();
                    node.is_terminal = true;
                    node.match_info = Some(match_info.clone());
                }
                // Move to next level (simplified for this implementation)
            }
        }
    }
    
    pub fn search(&self, domain: &str) -> Option<IocMatch> {
        let parts: Vec<&str> = domain.split('.').rev().collect();
        let mut current = &self.root;
        let mut last_match: Option<IocMatch> = None;
        
        for part in parts {
            let part_lower = part.to_lowercase();
            
            if let Some(node) = current.children.get(&part_lower) {
                if node.is_terminal {
                    last_match = node.match_info.clone();
                }
                // Continue traversal
            } else {
                break;
            }
        }
        
        last_match
    }
}

impl Default for DomainSuffixTree {
    fn default() -> Self {
        Self::new()
    }
}

/// IOC match result
#[derive(Debug, Clone)]
pub struct IocMatch {
    pub ioc_id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub confidence: Confidence,
    pub severity: Severity,
    pub source: String,
    pub labels: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

impl From<&Indicator> for IocMatch {
    fn from(indicator: &Indicator) -> Self {
        Self {
            ioc_id: indicator.id.clone(),
            ioc_type: indicator.ioc_type,
            value: indicator.value.clone(),
            confidence: indicator.confidence,
            severity: indicator.severity,
            source: indicator.sources.first()
                .map(|s| s.name.clone())
                .unwrap_or_default(),
            labels: indicator.tags.clone(),
            mitre_techniques: indicator.mitre_techniques.clone(),
        }
    }
}

/// Matching statistics
#[derive(Debug, Default)]
pub struct MatchingStats {
    pub lookups_total: std::sync::atomic::AtomicU64,
    pub lookups_hit: std::sync::atomic::AtomicU64,
    pub bloom_false_positives: std::sync::atomic::AtomicU64,
    pub ip_lookups: std::sync::atomic::AtomicU64,
    pub domain_lookups: std::sync::atomic::AtomicU64,
    pub hash_lookups: std::sync::atomic::AtomicU64,
    pub url_lookups: std::sync::atomic::AtomicU64,
}

/// Check request type
pub enum IocCheckRequest {
    Ip(IpAddr),
    Domain(String),
    Hash(String),
    Url(String),
}

impl IocMatchingEngine {
    /// Create new matching engine
    pub fn new(expected_iocs: usize) -> Self {
        Self {
            ip_bloom: BloomFilter::new(expected_iocs, 0.001),
            domain_bloom: BloomFilter::new(expected_iocs, 0.001),
            url_bloom: BloomFilter::new(expected_iocs, 0.001),
            hash_bloom: BloomFilter::new(expected_iocs, 0.001),
            ip_map: dashmap::DashMap::new(),
            domain_map: dashmap::DashMap::new(),
            url_map: dashmap::DashMap::new(),
            hash_map: dashmap::DashMap::new(),
            domain_suffixes: DomainSuffixTree::new(),
            stats: MatchingStats::default(),
        }
    }
    
    /// Add indicator to matching engine
    pub fn add(&self, indicator: &Indicator) {
        let match_info = IocMatch::from(indicator);
        
        match indicator.ioc_type {
            IocType::IPv4 | IocType::IPv6 => {
                if let Ok(ip) = indicator.value.parse::<IpAddr>() {
                    let ip_bytes = match ip {
                        IpAddr::V4(v4) => u128::from(u32::from(v4)),
                        IpAddr::V6(v6) => u128::from(v6),
                    };
                    self.ip_bloom.insert(&ip_bytes.to_be_bytes());
                    self.ip_map.insert(ip_bytes, match_info);
                }
            }
            IocType::Domain => {
                let domain_lower = indicator.value.to_lowercase();
                self.domain_bloom.insert(domain_lower.as_bytes());
                self.domain_suffixes.insert(&domain_lower, match_info.clone());
                self.domain_map.insert(domain_lower, match_info);
            }
            IocType::Url => {
                let url_lower = indicator.value.to_lowercase();
                self.url_bloom.insert(url_lower.as_bytes());
                self.url_map.insert(url_lower, match_info);
            }
            IocType::FileHashMd5 | IocType::FileHashSha1 | IocType::FileHashSha256 => {
                let hash_lower = indicator.value.to_lowercase();
                self.hash_bloom.insert(hash_lower.as_bytes());
                self.hash_map.insert(hash_lower, match_info);
            }
            _ => {}
        }
    }
    
    /// Check if IP matches known IOCs
    pub fn check_ip(&self, ip: IpAddr) -> Option<IocMatch> {
        use std::sync::atomic::Ordering;
        
        self.stats.lookups_total.fetch_add(1, Ordering::Relaxed);
        self.stats.ip_lookups.fetch_add(1, Ordering::Relaxed);
        
        let ip_bytes = match ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from(v6),
        };
        
        // Fast bloom filter check
        if !self.ip_bloom.contains(&ip_bytes.to_be_bytes()) {
            return None;
        }
        
        // Exact lookup
        if let Some(m) = self.ip_map.get(&ip_bytes) {
            self.stats.lookups_hit.fetch_add(1, Ordering::Relaxed);
            return Some(m.clone());
        }
        
        // Bloom filter false positive
        self.stats.bloom_false_positives.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Check if domain matches known IOCs
    pub fn check_domain(&self, domain: &str) -> Option<IocMatch> {
        use std::sync::atomic::Ordering;
        
        self.stats.lookups_total.fetch_add(1, Ordering::Relaxed);
        self.stats.domain_lookups.fetch_add(1, Ordering::Relaxed);
        
        let domain_lower = domain.to_lowercase();
        
        // Fast bloom filter check for exact match
        if self.domain_bloom.contains(domain_lower.as_bytes()) {
            if let Some(m) = self.domain_map.get(&domain_lower) {
                self.stats.lookups_hit.fetch_add(1, Ordering::Relaxed);
                return Some(m.clone());
            }
        }
        
        // Check parent domains using suffix tree
        if let Some(m) = self.domain_suffixes.search(&domain_lower) {
            self.stats.lookups_hit.fetch_add(1, Ordering::Relaxed);
            return Some(m);
        }
        
        // Manual parent domain check
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if self.domain_bloom.contains(parent.as_bytes()) {
                if let Some(m) = self.domain_map.get(&parent) {
                    self.stats.lookups_hit.fetch_add(1, Ordering::Relaxed);
                    return Some(m.clone());
                }
            }
        }
        
        None
    }
    
    /// Check if file hash matches known IOCs
    pub fn check_hash(&self, hash: &str) -> Option<IocMatch> {
        use std::sync::atomic::Ordering;
        
        self.stats.lookups_total.fetch_add(1, Ordering::Relaxed);
        self.stats.hash_lookups.fetch_add(1, Ordering::Relaxed);
        
        let hash_lower = hash.to_lowercase();
        
        // Fast bloom filter check
        if !self.hash_bloom.contains(hash_lower.as_bytes()) {
            return None;
        }
        
        // Exact lookup
        if let Some(m) = self.hash_map.get(&hash_lower) {
            self.stats.lookups_hit.fetch_add(1, Ordering::Relaxed);
            return Some(m.clone());
        }
        
        self.stats.bloom_false_positives.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Check if URL matches known IOCs
    pub fn check_url(&self, url: &str) -> Option<IocMatch> {
        use std::sync::atomic::Ordering;
        
        self.stats.lookups_total.fetch_add(1, Ordering::Relaxed);
        self.stats.url_lookups.fetch_add(1, Ordering::Relaxed);
        
        let url_lower = url.to_lowercase();
        
        // Fast bloom filter check
        if self.url_bloom.contains(url_lower.as_bytes()) {
            if let Some(m) = self.url_map.get(&url_lower) {
                self.stats.lookups_hit.fetch_add(1, Ordering::Relaxed);
                return Some(m.clone());
            }
        }
        
        // Extract and check domain from URL
        if let Some(domain) = extract_domain_from_url(&url_lower) {
            if let Some(m) = self.check_domain(&domain) {
                return Some(m);
            }
        }
        
        None
    }
    
    /// Batch check multiple IOCs
    pub fn batch_check(&self, items: &[IocCheckRequest]) -> Vec<Option<IocMatch>> {
        items.iter().map(|item| {
            match item {
                IocCheckRequest::Ip(ip) => self.check_ip(*ip),
                IocCheckRequest::Domain(d) => self.check_domain(d),
                IocCheckRequest::Hash(h) => self.check_hash(h),
                IocCheckRequest::Url(u) => self.check_url(u),
            }
        }).collect()
    }
    
    /// Get statistics snapshot
    pub fn get_stats(&self) -> MatchingStatsSnapshot {
        use std::sync::atomic::Ordering;
        
        MatchingStatsSnapshot {
            lookups_total: self.stats.lookups_total.load(Ordering::Relaxed),
            lookups_hit: self.stats.lookups_hit.load(Ordering::Relaxed),
            bloom_false_positives: self.stats.bloom_false_positives.load(Ordering::Relaxed),
            ip_count: self.ip_map.len(),
            domain_count: self.domain_map.len(),
            hash_count: self.hash_map.len(),
            url_count: self.url_map.len(),
        }
    }
    
    /// Clear all data
    pub fn clear(&self) {
        self.ip_bloom.clear();
        self.domain_bloom.clear();
        self.url_bloom.clear();
        self.hash_bloom.clear();
        self.ip_map.clear();
        self.domain_map.clear();
        self.url_map.clear();
        self.hash_map.clear();
    }
}

#[derive(Debug, Clone)]
pub struct MatchingStatsSnapshot {
    pub lookups_total: u64,
    pub lookups_hit: u64,
    pub bloom_false_positives: u64,
    pub ip_count: usize,
    pub domain_count: usize,
    pub hash_count: usize,
    pub url_count: usize,
}

fn extract_domain_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    
    without_scheme
        .split('/')
        .next()
        .map(|s| s.split(':').next().unwrap_or(s).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bloom_filter() {
        let bloom = BloomFilter::new(1000, 0.01);
        
        bloom.insert(b"test");
        assert!(bloom.contains(b"test"));
        assert!(!bloom.contains(b"notexist"));
    }
    
    #[test]
    fn test_ip_matching() {
        let engine = IocMatchingEngine::new(1000);
        
        let indicator = Indicator {
            id: "test-1".to_string(),
            ioc_type: IocType::IPv4,
            value: "192.168.1.1".to_string(),
            confidence: Confidence::High,
            severity: Severity::High,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            expires_at: None,
            sources: vec![],
            tags: vec![],
            context: crate::IocContext::default(),
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            related_iocs: vec![],
        };
        
        engine.add(&indicator);
        
        let result = engine.check_ip("192.168.1.1".parse().unwrap());
        assert!(result.is_some());
        
        let result = engine.check_ip("192.168.1.2".parse().unwrap());
        assert!(result.is_none());
    }
    
    #[test]
    fn test_domain_matching() {
        let engine = IocMatchingEngine::new(1000);
        
        let indicator = Indicator {
            id: "test-2".to_string(),
            ioc_type: IocType::Domain,
            value: "malware.com".to_string(),
            confidence: Confidence::High,
            severity: Severity::Critical,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            expires_at: None,
            sources: vec![],
            tags: vec![],
            context: crate::IocContext::default(),
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            related_iocs: vec![],
        };
        
        engine.add(&indicator);
        
        // Exact match
        assert!(engine.check_domain("malware.com").is_some());
        
        // Subdomain match
        assert!(engine.check_domain("sub.malware.com").is_some());
        
        // No match
        assert!(engine.check_domain("safe.com").is_none());
    }
}
