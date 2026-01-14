//! Feature Extraction

use serde::{Deserialize, Serialize};

/// Network flow features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    /// Bytes per second
    pub bytes_per_second: f64,
    /// Packets per second
    pub packets_per_second: f64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Flow duration (seconds)
    pub duration: f64,
    /// Source port entropy
    pub src_port_entropy: f64,
    /// Destination port entropy
    pub dst_port_entropy: f64,
    /// Protocol distribution (TCP, UDP, ICMP, etc.)
    pub protocol_distribution: [f64; 10],
    /// Time of day (0-24)
    pub time_of_day: f64,
    /// Day of week (0-6)
    pub day_of_week: f64,
    /// Geographic distance (src to dst)
    pub geo_distance: f64,
}

impl FlowFeatures {
    /// Convert to feature vector
    pub fn to_vector(&self) -> Vec<f64> {
        let mut v = vec![
            self.bytes_per_second,
            self.packets_per_second,
            self.avg_packet_size,
            self.duration,
            self.src_port_entropy,
            self.dst_port_entropy,
            self.time_of_day,
            self.day_of_week,
            self.geo_distance,
        ];
        v.extend_from_slice(&self.protocol_distribution);
        v
    }
}

/// DNS query for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Domain name
    pub domain: String,
    /// Query type
    pub query_type: String,
    /// Source IP
    pub source_ip: String,
    /// Timestamp
    pub timestamp: u64,
}

/// DNS features for ML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFeatures {
    /// Domain length
    pub length: f64,
    /// Character entropy
    pub entropy: f64,
    /// Consonant ratio
    pub consonant_ratio: f64,
    /// Digit ratio
    pub digit_ratio: f64,
    /// Max label length
    pub max_label_length: f64,
    /// Number of labels
    pub label_count: f64,
    /// Bigram frequency score
    pub bigram_score: f64,
    /// Is numeric TLD
    pub numeric_tld: f64,
}

impl DnsFeatures {
    /// Extract features from domain
    pub fn from_domain(domain: &str) -> Self {
        let length = domain.len() as f64;
        let entropy = calculate_entropy(domain);
        let consonant_ratio = calculate_consonant_ratio(domain);
        let digit_ratio = calculate_digit_ratio(domain);
        let labels: Vec<&str> = domain.split('.').collect();
        let max_label_length = labels.iter().map(|l| l.len()).max().unwrap_or(0) as f64;
        let label_count = labels.len() as f64;
        
        Self {
            length,
            entropy,
            consonant_ratio,
            digit_ratio,
            max_label_length,
            label_count,
            bigram_score: calculate_bigram_score(domain),
            numeric_tld: if labels.last().map(|l| l.chars().all(|c| c.is_numeric())).unwrap_or(false) { 1.0 } else { 0.0 },
        }
    }

    /// Convert to feature vector
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.length,
            self.entropy,
            self.consonant_ratio,
            self.digit_ratio,
            self.max_label_length,
            self.label_count,
            self.bigram_score,
            self.numeric_tld,
        ]
    }
}

/// User session for UBA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    /// User ID
    pub user_id: String,
    /// Applications accessed
    pub applications: Vec<String>,
    /// Data volume (bytes)
    pub data_volume: u64,
    /// Geographic locations
    pub locations: Vec<String>,
    /// Access times
    pub access_times: Vec<u64>,
    /// Device ID
    pub device_id: String,
}

/// TLS fingerprint (JA3/JA4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFingerprint {
    /// JA3 hash
    pub ja3: String,
    /// JA4 fingerprint
    pub ja4: Option<String>,
    /// TLS version
    pub version: String,
    /// Cipher suites
    pub cipher_suites: Vec<u16>,
    /// Extensions
    pub extensions: Vec<u16>,
}

// Helper functions
fn calculate_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn calculate_consonant_ratio(s: &str) -> f64 {
    let consonants: &[char] = &['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 
                                 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'z'];
    let alpha: Vec<char> = s.chars().filter(|c| c.is_alphabetic()).collect();
    if alpha.is_empty() { return 0.0; }
    let cons_count = alpha.iter().filter(|c| consonants.contains(&c.to_ascii_lowercase())).count();
    cons_count as f64 / alpha.len() as f64
}

fn calculate_digit_ratio(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let digit_count = s.chars().filter(|c| c.is_numeric()).count();
    digit_count as f64 / s.len() as f64
}

fn calculate_bigram_score(domain: &str) -> f64 {
    // Simplified: check for common English bigrams
    let common_bigrams = ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"];
    let domain_lower = domain.to_lowercase();
    let mut score = 0.0;
    for bigram in &common_bigrams {
        if domain_lower.contains(bigram) {
            score += 0.1;
        }
    }
    score.min(1.0)
}
