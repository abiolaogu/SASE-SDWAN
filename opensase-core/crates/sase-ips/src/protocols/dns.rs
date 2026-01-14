//! DNS Protocol Analyzer
//!
//! Analyzes DNS queries and responses for security threats
//! including DGA detection, tunneling, and domain classification.

use std::collections::HashSet;

/// DNS analysis verdict
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsVerdict {
    Allow,
    Block(&'static str),
    Alert(&'static str),
    NeedMore,
}

/// Parsed DNS query
#[derive(Clone, Debug, Default)]
pub struct DnsQuery {
    /// Transaction ID
    pub id: u16,
    
    /// Query domain name
    pub qname: String,
    
    /// Query type (A, AAAA, MX, etc.)
    pub qtype: u16,
    
    /// Query class
    pub qclass: u16,
    
    /// Is response
    pub is_response: bool,
    
    /// Domain labels
    pub labels: Vec<String>,
}

/// DNS analyzer configuration
#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// Detect DGA domains
    pub detect_dga: bool,
    
    /// Detect DNS tunneling
    pub detect_tunneling: bool,
    
    /// Blocked domains
    pub blocked_domains: HashSet<String>,
    
    /// Blocked TLDs
    pub blocked_tlds: HashSet<String>,
    
    /// Max label length (tunneling indicator)
    pub max_label_length: usize,
    
    /// Max subdomain count
    pub max_subdomain_count: usize,
    
    /// Max query length
    pub max_query_length: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            detect_dga: true,
            detect_tunneling: true,
            blocked_domains: HashSet::new(),
            blocked_tlds: HashSet::new(),
            max_label_length: 63,  // RFC limit
            max_subdomain_count: 10,
            max_query_length: 253, // RFC limit
        }
    }
}

/// DNS protocol analyzer
pub struct DnsAnalyzer {
    config: DnsConfig,
}

impl DnsAnalyzer {
    /// Create new analyzer
    pub fn new(config: DnsConfig) -> Self {
        Self { config }
    }
    
    /// Analyze DNS query
    pub fn analyze_query(&self, data: &[u8]) -> DnsVerdict {
        let query = match self.parse_dns(data) {
            Some(q) => q,
            None => return DnsVerdict::NeedMore,
        };
        
        // Check query length
        if query.qname.len() > self.config.max_query_length {
            return DnsVerdict::Block("DNS query too long");
        }
        
        // Check blocked domains
        if self.is_blocked_domain(&query.qname) {
            return DnsVerdict::Block("Blocked domain");
        }
        
        // Check blocked TLDs
        if let Some(tld) = query.labels.last() {
            if self.config.blocked_tlds.contains(&tld.to_lowercase()) {
                return DnsVerdict::Block("Blocked TLD");
            }
        }
        
        // DGA detection
        if self.config.detect_dga && self.detect_dga(&query) {
            return DnsVerdict::Alert("Possible DGA domain");
        }
        
        // DNS tunneling detection
        if self.config.detect_tunneling && self.detect_tunneling(&query) {
            return DnsVerdict::Alert("Possible DNS tunneling");
        }
        
        DnsVerdict::Allow
    }
    
    /// Parse DNS packet
    fn parse_dns(&self, data: &[u8]) -> Option<DnsQuery> {
        if data.len() < 12 {
            return None; // DNS header is 12 bytes
        }
        
        let id = ((data[0] as u16) << 8) | (data[1] as u16);
        let flags = ((data[2] as u16) << 8) | (data[3] as u16);
        let is_response = (flags & 0x8000) != 0;
        let qdcount = ((data[4] as u16) << 8) | (data[5] as u16);
        
        if qdcount == 0 {
            return None;
        }
        
        // Parse question section
        let (qname, labels, end_pos) = self.parse_name(data, 12)?;
        
        if end_pos + 4 > data.len() {
            return None;
        }
        
        let qtype = ((data[end_pos] as u16) << 8) | (data[end_pos + 1] as u16);
        let qclass = ((data[end_pos + 2] as u16) << 8) | (data[end_pos + 3] as u16);
        
        Some(DnsQuery {
            id,
            qname,
            qtype,
            qclass,
            is_response,
            labels,
        })
    }
    
    /// Parse DNS name
    fn parse_name(&self, data: &[u8], start: usize) -> Option<(String, Vec<String>, usize)> {
        let mut pos = start;
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut jump_pos = 0;
        
        loop {
            if pos >= data.len() {
                return None;
            }
            
            let len = data[pos] as usize;
            
            if len == 0 {
                // End of name
                if !jumped {
                    pos += 1;
                }
                break;
            }
            
            // Check for compression pointer
            if (len & 0xC0) == 0xC0 {
                if pos + 1 >= data.len() {
                    return None;
                }
                let offset = (((len & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
                if !jumped {
                    jump_pos = pos + 2;
                }
                jumped = true;
                pos = offset;
                continue;
            }
            
            pos += 1;
            
            if pos + len > data.len() {
                return None;
            }
            
            if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
                labels.push(label.to_string());
            }
            
            pos += len;
        }
        
        let qname = labels.join(".");
        let final_pos = if jumped { jump_pos } else { pos };
        
        Some((qname, labels, final_pos))
    }
    
    /// Check if domain is blocked
    fn is_blocked_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // Exact match
        if self.config.blocked_domains.contains(&domain_lower) {
            return true;
        }
        
        // Subdomain match
        for blocked in &self.config.blocked_domains {
            if domain_lower.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }
        
        false
    }
    
    /// Detect DGA (Domain Generation Algorithm) domains
    fn detect_dga(&self, query: &DnsQuery) -> bool {
        // Get the main domain (excluding TLD)
        if query.labels.len() < 2 {
            return false;
        }
        
        let domain_part = &query.labels[query.labels.len() - 2];
        
        // Check for high entropy (random-looking)
        let entropy = self.calculate_entropy(domain_part);
        if entropy > 4.0 {
            return true;
        }
        
        // Check for unusual character distribution
        let consonant_ratio = self.consonant_ratio(domain_part);
        if consonant_ratio > 0.8 {
            return true;
        }
        
        // Check for excessive length with numbers
        if domain_part.len() > 15 && domain_part.chars().any(|c| c.is_numeric()) {
            let digit_count = domain_part.chars().filter(|c| c.is_numeric()).count();
            if digit_count > domain_part.len() / 3 {
                return true;
            }
        }
        
        // Check for lack of vowels
        let vowel_count = domain_part
            .to_lowercase()
            .chars()
            .filter(|c| "aeiou".contains(*c))
            .count();
        
        if domain_part.len() > 8 && vowel_count == 0 {
            return true;
        }
        
        false
    }
    
    /// Calculate Shannon entropy
    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        
        let mut freq = [0u32; 256];
        for &byte in s.as_bytes() {
            freq[byte as usize] += 1;
        }
        
        let len = s.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &freq {
            if count > 0 {
                let p = (count as f64) / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Calculate consonant ratio
    fn consonant_ratio(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        
        let consonants = "bcdfghjklmnpqrstvwxyz";
        let vowels = "aeiou";
        
        let s_lower = s.to_lowercase();
        let letter_count = s_lower.chars().filter(|c| c.is_alphabetic()).count();
        
        if letter_count == 0 {
            return 0.0;
        }
        
        let consonant_count = s_lower.chars()
            .filter(|c| consonants.contains(*c))
            .count();
        
        consonant_count as f64 / letter_count as f64
    }
    
    /// Detect DNS tunneling
    fn detect_tunneling(&self, query: &DnsQuery) -> bool {
        // Check for too many subdomains
        if query.labels.len() > self.config.max_subdomain_count {
            return true;
        }
        
        // Check for very long labels (often base64/hex encoded data)
        for label in &query.labels[..query.labels.len().saturating_sub(1)] {
            if label.len() > 30 {
                // Check for base64-like patterns
                if self.looks_like_encoded(label) {
                    return true;
                }
            }
        }
        
        // Check total query length
        if query.qname.len() > 100 {
            // Long queries are suspicious
            let entropy = self.calculate_entropy(&query.qname);
            if entropy > 3.5 {
                return true;
            }
        }
        
        // Check for TXT record queries to suspicious domains
        if query.qtype == 16 {
            // TXT record
            // High entropy subdomain before a seemingly legit TLD
            if query.labels.len() >= 2 {
                let subdomain = &query.labels[0];
                let entropy = self.calculate_entropy(subdomain);
                if entropy > 4.0 && subdomain.len() > 20 {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Check if string looks like encoded data
    fn looks_like_encoded(&self, s: &str) -> bool {
        // Check for base64 pattern
        let base64_chars: HashSet<char> = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            .chars()
            .collect();
        
        let matching = s.chars()
            .filter(|c| base64_chars.contains(c))
            .count();
        
        if matching as f64 / s.len() as f64 > 0.9 {
            return true;
        }
        
        // Check for hex pattern
        let hex_chars: HashSet<char> = 
            "0123456789abcdefABCDEF"
            .chars()
            .collect();
        
        let hex_matching = s.chars()
            .filter(|c| hex_chars.contains(c))
            .count();
        
        if hex_matching as f64 / s.len() as f64 > 0.95 {
            return true;
        }
        
        false
    }
}

impl Default for DnsAnalyzer {
    fn default() -> Self {
        Self::new(DnsConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dga_detection() {
        let analyzer = DnsAnalyzer::default();
        
        // Build fake queries
        let normal_query = DnsQuery {
            qname: "www.google.com".into(),
            labels: vec!["www".into(), "google".into(), "com".into()],
            ..Default::default()
        };
        
        let dga_query = DnsQuery {
            qname: "sdfj7k3nv9x2m.com".into(),
            labels: vec!["sdfj7k3nv9x2m".into(), "com".into()],
            ..Default::default()
        };
        
        assert!(!analyzer.detect_dga(&normal_query));
        assert!(analyzer.detect_dga(&dga_query));
    }

    #[test]
    fn test_entropy_calculation() {
        let analyzer = DnsAnalyzer::default();
        
        // Low entropy (repeated chars)
        let low = analyzer.calculate_entropy("aaaaaaa");
        
        // High entropy (random-ish)
        let high = analyzer.calculate_entropy("abc123xyz");
        
        assert!(low < high);
        assert!(low < 1.0);
    }
}
