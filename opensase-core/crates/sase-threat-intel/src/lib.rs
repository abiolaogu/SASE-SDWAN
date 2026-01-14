//! OpenSASE Threat Intelligence Platform (OSTIP)
//!
//! Comprehensive threat intelligence platform that aggregates, correlates,
//! and operationalizes intelligence from multiple sources.
//!
//! # Features
//! - Multi-source feed aggregation (STIX/TAXII, MISP, OpenCTI)
//! - Real-time IoC correlation and enrichment
//! - MITRE ATT&CK framework mapping
//! - Automatic distribution to SASE components
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    THREAT INTELLIGENCE PLATFORM                  │
//! ├─────────────────────────────────────────────────────────────────┤
//! │ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
//! │ │ STIX/TAXII  │  │    MISP     │  │  OpenCTI    │  ... Feeds  │
//! │ └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
//! │        └────────────────┼────────────────┘                      │
//! │                         ▼                                       │
//! │               ┌─────────────────────┐                          │
//! │               │   Feed Aggregator   │                          │
//! │               └──────────┬──────────┘                          │
//! │                          ▼                                      │
//! │               ┌─────────────────────┐                          │
//! │               │  Correlation Engine │                          │
//! │               └──────────┬──────────┘                          │
//! │                          ▼                                      │
//! │  ┌──────────────────────────────────────────────────────┐      │
//! │  │                    IoC Database                       │      │
//! │  │  IPs | Domains | Hashes | URLs | Emails | CVEs       │      │
//! │  └──────────────────────────────────────────────────────┘      │
//! │                          │                                      │
//! │        ┌─────────────────┼─────────────────┐                   │
//! │        ▼                 ▼                 ▼                   │
//! │  ┌──────────┐      ┌──────────┐      ┌──────────┐             │
//! │  │   XDP    │      │  L7 GW   │      │   IPS    │             │
//! │  │ Blocklist│      │ URL Filt │      │  Rules   │             │
//! │  └──────────┘      └──────────┘      └──────────┘             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

pub mod feeds;
pub mod stix;
pub mod correlator;
pub mod enrichment;
pub mod mitre;
pub mod distribution;
pub mod sources;
pub mod sinkhole;

// =============================================================================
// Indicator of Compromise (IoC) Types
// =============================================================================

/// Unique identifier for an IoC
pub type IocId = String;

/// Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub id: IocId,
    pub ioc_type: IocType,
    pub value: String,
    pub confidence: Confidence,
    pub severity: Severity,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub sources: Vec<IntelSource>,
    pub tags: Vec<String>,
    pub context: IocContext,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub related_iocs: Vec<IocId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    IPv4,
    IPv6,
    Domain,
    Url,
    FileHashMd5,
    FileHashSha1,
    FileHashSha256,
    Email,
    Cve,
    JarmHash,
    Ja3Hash,
    UserAgent,
    SslCertHash,
    Asn,
    Cidr,
    RegistryKey,
    Mutex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Unknown = 0,
    Low = 25,
    Medium = 50,
    High = 75,
    Confirmed = 100,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Intelligence source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSource {
    pub name: String,
    pub feed_id: String,
    pub reliability: Reliability,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub reference_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reliability {
    A, // Completely reliable
    B, // Usually reliable
    C, // Fairly reliable
    D, // Not usually reliable
    E, // Unreliable
    F, // Cannot be judged
}

/// Additional context for an IoC
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocContext {
    pub threat_type: Option<ThreatType>,
    pub malware_family: Option<String>,
    pub campaign: Option<String>,
    pub threat_actor: Option<String>,
    pub description: Option<String>,
    pub kill_chain_phases: Vec<String>,
    pub geo_location: Option<GeoLocation>,
    pub whois: Option<WhoisData>,
    pub dns_records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Botnet,
    C2,
    Phishing,
    Spam,
    Scanner,
    Exploit,
    Ransomware,
    Apt,
    Cryptominer,
    Proxy,
    Tor,
    Vpn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisData {
    pub registrar: Option<String>,
    pub created_date: Option<String>,
    pub updated_date: Option<String>,
    pub expires_date: Option<String>,
    pub registrant_org: Option<String>,
    pub registrant_country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub first_seen: chrono::DateTime<chrono::Utc>,
}

// =============================================================================
// Threat Intelligence Feed
// =============================================================================

/// Configuration for a threat intelligence feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    pub id: String,
    pub name: String,
    pub feed_type: FeedType,
    pub url: String,
    pub api_key: Option<String>,
    pub poll_interval: Duration,
    pub enabled: bool,
    pub reliability: Reliability,
    pub default_confidence: Confidence,
    pub ioc_types: Vec<IocType>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedType {
    StixTaxii,
    Misp,
    OpenCti,
    CsvFile,
    JsonApi,
    RssFeed,
    Custom,
}

/// Feed status and statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedStatus {
    pub feed_id: String,
    pub last_poll: Option<chrono::DateTime<chrono::Utc>>,
    pub next_poll: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
    pub indicators_total: u64,
    pub indicators_active: u64,
    pub indicators_expired: u64,
    pub health: FeedHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FeedHealth {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Error,
}

// =============================================================================
// Threat Intelligence Service
// =============================================================================

/// Main threat intelligence service
pub struct ThreatIntelService {
    config: ThreatIntelConfig,
    feeds: feeds::FeedAggregator,
    correlator: correlator::Correlator,
    enricher: enrichment::Enricher,
    distributor: distribution::Distributor,
    indicators: dashmap::DashMap<IocId, Indicator>,
    stats: ThreatIntelStats,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    /// Maximum indicators to keep in memory
    pub max_indicators: usize,
    /// Default TTL for indicators without expiry
    pub default_ttl_days: u32,
    /// Minimum confidence to distribute
    pub min_distribute_confidence: Confidence,
    /// Enable enrichment
    pub enable_enrichment: bool,
    /// Enable MITRE mapping
    pub enable_mitre_mapping: bool,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            max_indicators: 10_000_000,
            default_ttl_days: 30,
            min_distribute_confidence: Confidence::Medium,
            enable_enrichment: true,
            enable_mitre_mapping: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct ThreatIntelStats {
    pub indicators_total: std::sync::atomic::AtomicU64,
    pub indicators_by_type: dashmap::DashMap<IocType, u64>,
    pub feeds_active: std::sync::atomic::AtomicU32,
    pub lookups_total: std::sync::atomic::AtomicU64,
    pub lookups_hits: std::sync::atomic::AtomicU64,
    pub distributions_total: std::sync::atomic::AtomicU64,
}

impl ThreatIntelService {
    pub fn new(config: ThreatIntelConfig) -> Self {
        Self {
            config,
            feeds: feeds::FeedAggregator::new(),
            correlator: correlator::Correlator::new(),
            enricher: enrichment::Enricher::new(),
            distributor: distribution::Distributor::new(),
            indicators: dashmap::DashMap::new(),
            stats: ThreatIntelStats::default(),
        }
    }
    
    /// Add a new feed
    pub fn add_feed(&self, config: FeedConfig) {
        self.feeds.add_feed(config);
    }
    
    /// Lookup an indicator
    pub fn lookup(&self, ioc_type: IocType, value: &str) -> Option<Indicator> {
        use std::sync::atomic::Ordering;
        
        self.stats.lookups_total.fetch_add(1, Ordering::Relaxed);
        
        let key = format!("{}:{}", ioc_type_to_string(ioc_type), value.to_lowercase());
        
        if let Some(indicator) = self.indicators.get(&key) {
            self.stats.lookups_hits.fetch_add(1, Ordering::Relaxed);
            return Some(indicator.clone());
        }
        
        None
    }
    
    /// Lookup IP address
    pub fn lookup_ip(&self, ip: IpAddr) -> Option<Indicator> {
        let ioc_type = match ip {
            IpAddr::V4(_) => IocType::IPv4,
            IpAddr::V6(_) => IocType::IPv6,
        };
        self.lookup(ioc_type, &ip.to_string())
    }
    
    /// Lookup domain
    pub fn lookup_domain(&self, domain: &str) -> Option<Indicator> {
        self.lookup(IocType::Domain, domain)
    }
    
    /// Lookup URL
    pub fn lookup_url(&self, url: &str) -> Option<Indicator> {
        self.lookup(IocType::Url, url)
    }
    
    /// Lookup file hash
    pub fn lookup_hash(&self, hash: &str) -> Option<Indicator> {
        // Detect hash type by length
        let ioc_type = match hash.len() {
            32 => IocType::FileHashMd5,
            40 => IocType::FileHashSha1,
            64 => IocType::FileHashSha256,
            _ => return None,
        };
        self.lookup(ioc_type, hash)
    }
    
    /// Ingest an indicator
    pub fn ingest(&self, indicator: Indicator) {
        use std::sync::atomic::Ordering;
        
        let key = format!("{}:{}", ioc_type_to_string(indicator.ioc_type), indicator.value.to_lowercase());
        
        // Merge if exists
        if let Some(mut existing) = self.indicators.get_mut(&key) {
            // Update last seen
            existing.last_seen = indicator.last_seen;
            
            // Merge sources
            for source in indicator.sources {
                if !existing.sources.iter().any(|s| s.feed_id == source.feed_id) {
                    existing.sources.push(source);
                }
            }
            
            // Update confidence based on number of sources
            if existing.sources.len() >= 3 {
                existing.confidence = Confidence::High;
            } else if existing.sources.len() >= 2 {
                existing.confidence = std::cmp::max(existing.confidence, Confidence::Medium);
            }
            
            return;
        }
        
        // Insert new
        self.indicators.insert(key, indicator.clone());
        self.stats.indicators_total.fetch_add(1, Ordering::Relaxed);
        
        // Update type counter
        self.stats.indicators_by_type
            .entry(indicator.ioc_type)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }
    
    /// Get statistics snapshot
    pub fn get_stats(&self) -> ThreatIntelSnapshot {
        use std::sync::atomic::Ordering;
        
        ThreatIntelSnapshot {
            indicators_total: self.stats.indicators_total.load(Ordering::Relaxed),
            feeds_active: self.stats.feeds_active.load(Ordering::Relaxed),
            lookups_total: self.stats.lookups_total.load(Ordering::Relaxed),
            lookups_hits: self.stats.lookups_hits.load(Ordering::Relaxed),
            distributions_total: self.stats.distributions_total.load(Ordering::Relaxed),
        }
    }
    
    /// Cleanup expired indicators
    pub fn cleanup_expired(&self) {
        let now = chrono::Utc::now();
        
        self.indicators.retain(|_, indicator| {
            if let Some(expires) = indicator.expires_at {
                expires > now
            } else {
                true
            }
        });
    }
}

#[derive(Debug, Clone)]
pub struct ThreatIntelSnapshot {
    pub indicators_total: u64,
    pub feeds_active: u32,
    pub lookups_total: u64,
    pub lookups_hits: u64,
    pub distributions_total: u64,
}

fn ioc_type_to_string(ioc_type: IocType) -> &'static str {
    match ioc_type {
        IocType::IPv4 => "ipv4",
        IocType::IPv6 => "ipv6",
        IocType::Domain => "domain",
        IocType::Url => "url",
        IocType::FileHashMd5 => "md5",
        IocType::FileHashSha1 => "sha1",
        IocType::FileHashSha256 => "sha256",
        IocType::Email => "email",
        IocType::Cve => "cve",
        IocType::JarmHash => "jarm",
        IocType::Ja3Hash => "ja3",
        IocType::UserAgent => "useragent",
        IocType::SslCertHash => "sslcert",
        IocType::Asn => "asn",
        IocType::Cidr => "cidr",
        IocType::RegistryKey => "regkey",
        IocType::Mutex => "mutex",
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_indicator_lookup() {
        let service = ThreatIntelService::new(ThreatIntelConfig::default());
        
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
            tags: vec!["malware".to_string()],
            context: IocContext::default(),
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            related_iocs: vec![],
        };
        
        service.ingest(indicator);
        
        let result = service.lookup(IocType::IPv4, "192.168.1.1");
        assert!(result.is_some());
    }
}
