//! IoC Enrichment
//!
//! Context enrichment for indicators using external services.

use crate::{Indicator, IocType, IocContext, GeoLocation, WhoisData, DnsRecord};

/// Enrichment engine for adding context to indicators
pub struct Enricher {
    /// GeoIP database
    geoip: Option<GeoIpDb>,
    /// Enable passive DNS
    enable_pdns: bool,
    /// Enable WHOIS
    enable_whois: bool,
    /// Cache for enrichment results
    cache: dashmap::DashMap<String, EnrichmentCache>,
}

#[derive(Debug, Clone)]
struct EnrichmentCache {
    data: EnrichmentResult,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct EnrichmentResult {
    pub geo: Option<GeoLocation>,
    pub whois: Option<WhoisData>,
    pub dns_records: Vec<DnsRecord>,
    pub reputation_score: Option<i32>,
    pub first_seen_global: Option<chrono::DateTime<chrono::Utc>>,
    pub related_samples: Vec<String>,
    pub ssl_certificates: Vec<SslCertInfo>,
    pub additional_context: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SslCertInfo {
    pub fingerprint: String,
    pub issuer: String,
    pub subject: String,
    pub valid_from: String,
    pub valid_until: String,
}

struct GeoIpDb {
    // In production: MaxMind GeoLite2 database
}

impl Enricher {
    pub fn new() -> Self {
        Self {
            geoip: None,
            enable_pdns: true,
            enable_whois: true,
            cache: dashmap::DashMap::new(),
        }
    }
    
    /// Enrich an indicator with additional context
    pub async fn enrich(&self, indicator: &mut Indicator) -> EnrichmentResult {
        let cache_key = format!("{}:{}", indicator.ioc_type as u8, &indicator.value);
        
        // Check cache
        if let Some(cached) = self.cache.get(&cache_key) {
            if cached.expires_at > chrono::Utc::now() {
                self.apply_enrichment(indicator, &cached.data);
                return cached.data.clone();
            }
        }
        
        let mut result = EnrichmentResult::default();
        
        match indicator.ioc_type {
            IocType::IPv4 | IocType::IPv6 => {
                result.geo = self.lookup_geo(&indicator.value).await;
                if self.enable_pdns {
                    result.dns_records = self.lookup_pdns_ip(&indicator.value).await;
                }
                result.reputation_score = self.lookup_ip_reputation(&indicator.value).await;
            }
            IocType::Domain => {
                if self.enable_whois {
                    result.whois = self.lookup_whois(&indicator.value).await;
                }
                if self.enable_pdns {
                    result.dns_records = self.lookup_pdns_domain(&indicator.value).await;
                }
                result.reputation_score = self.lookup_domain_reputation(&indicator.value).await;
            }
            IocType::Url => {
                // Extract domain and enrich
                if let Some(domain) = extract_domain(&indicator.value) {
                    if self.enable_whois {
                        result.whois = self.lookup_whois(&domain).await;
                    }
                    result.reputation_score = self.lookup_url_reputation(&indicator.value).await;
                }
            }
            IocType::FileHashMd5 | IocType::FileHashSha1 | IocType::FileHashSha256 => {
                result.related_samples = self.lookup_hash_relations(&indicator.value).await;
                result.reputation_score = self.lookup_hash_reputation(&indicator.value).await;
            }
            _ => {}
        }
        
        // Apply to indicator
        self.apply_enrichment(indicator, &result);
        
        // Cache result
        let cache_entry = EnrichmentCache {
            data: result.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        };
        self.cache.insert(cache_key, cache_entry);
        
        result
    }
    
    fn apply_enrichment(&self, indicator: &mut Indicator, result: &EnrichmentResult) {
        if let Some(geo) = &result.geo {
            indicator.context.geo_location = Some(geo.clone());
        }
        
        if let Some(whois) = &result.whois {
            indicator.context.whois = Some(whois.clone());
        }
        
        indicator.context.dns_records = result.dns_records.clone();
        
        // Adjust severity based on reputation
        if let Some(score) = result.reputation_score {
            if score < -50 {
                indicator.severity = std::cmp::max(indicator.severity, crate::Severity::High);
            } else if score < -25 {
                indicator.severity = std::cmp::max(indicator.severity, crate::Severity::Medium);
            }
        }
    }
    
    async fn lookup_geo(&self, ip: &str) -> Option<GeoLocation> {
        // In production: MaxMind GeoLite2 lookup
        // Placeholder response
        Some(GeoLocation {
            country: "Unknown".to_string(),
            country_code: "XX".to_string(),
            city: None,
            asn: None,
            as_org: None,
        })
    }
    
    async fn lookup_whois(&self, domain: &str) -> Option<WhoisData> {
        // In production: WHOIS lookup via rdap or whois protocol
        None
    }
    
    async fn lookup_pdns_ip(&self, ip: &str) -> Vec<DnsRecord> {
        // Passive DNS lookup for IP
        Vec::new()
    }
    
    async fn lookup_pdns_domain(&self, domain: &str) -> Vec<DnsRecord> {
        // Passive DNS lookup for domain
        Vec::new()
    }
    
    async fn lookup_ip_reputation(&self, ip: &str) -> Option<i32> {
        // IP reputation score (-100 to 100)
        // In production: Query reputation services
        None
    }
    
    async fn lookup_domain_reputation(&self, domain: &str) -> Option<i32> {
        // Domain reputation score
        None
    }
    
    async fn lookup_url_reputation(&self, url: &str) -> Option<i32> {
        // URL reputation score
        None
    }
    
    async fn lookup_hash_reputation(&self, hash: &str) -> Option<i32> {
        // File hash reputation score
        None
    }
    
    async fn lookup_hash_relations(&self, hash: &str) -> Vec<String> {
        // Related malware samples
        Vec::new()
    }
}

impl Default for Enricher {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_domain(url: &str) -> Option<String> {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .map(|s| s.split(':').next().unwrap_or(s).to_string())
}

/// External enrichment sources
pub mod sources {
    /// VirusTotal API client
    pub struct VirusTotalClient {
        api_key: String,
        client: reqwest::Client,
    }
    
    impl VirusTotalClient {
        pub fn new(api_key: &str) -> Self {
            Self {
                api_key: api_key.to_string(),
                client: reqwest::Client::new(),
            }
        }
        
        pub async fn lookup_ip(&self, ip: &str) -> Option<VtIpReport> {
            let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
            
            let resp = self.client.get(&url)
                .header("x-apikey", &self.api_key)
                .send()
                .await
                .ok()?;
            
            resp.json().await.ok()
        }
        
        pub async fn lookup_domain(&self, domain: &str) -> Option<VtDomainReport> {
            let url = format!("https://www.virustotal.com/api/v3/domains/{}", domain);
            
            let resp = self.client.get(&url)
                .header("x-apikey", &self.api_key)
                .send()
                .await
                .ok()?;
            
            resp.json().await.ok()
        }
        
        pub async fn lookup_hash(&self, hash: &str) -> Option<VtFileReport> {
            let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
            
            let resp = self.client.get(&url)
                .header("x-apikey", &self.api_key)
                .send()
                .await
                .ok()?;
            
            resp.json().await.ok()
        }
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct VtIpReport {
        pub data: VtIpData,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct VtIpData {
        pub attributes: VtIpAttributes,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct VtIpAttributes {
        pub country: Option<String>,
        pub as_owner: Option<String>,
        pub last_analysis_stats: Option<VtAnalysisStats>,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct VtAnalysisStats {
        pub malicious: u32,
        pub suspicious: u32,
        pub harmless: u32,
        pub undetected: u32,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct VtDomainReport {
        pub data: serde_json::Value,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct VtFileReport {
        pub data: serde_json::Value,
    }
    
    /// AbuseIPDB client
    pub struct AbuseIpDbClient {
        api_key: String,
        client: reqwest::Client,
    }
    
    impl AbuseIpDbClient {
        pub fn new(api_key: &str) -> Self {
            Self {
                api_key: api_key.to_string(),
                client: reqwest::Client::new(),
            }
        }
        
        pub async fn check_ip(&self, ip: &str) -> Option<AbuseIpDbReport> {
            let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}", ip);
            
            let resp = self.client.get(&url)
                .header("Key", &self.api_key)
                .header("Accept", "application/json")
                .send()
                .await
                .ok()?;
            
            resp.json().await.ok()
        }
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct AbuseIpDbReport {
        pub data: AbuseIpDbData,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AbuseIpDbData {
        pub ip_address: String,
        pub abuse_confidence_score: u32,
        pub country_code: Option<String>,
        pub usage_type: Option<String>,
        pub isp: Option<String>,
        pub total_reports: u32,
    }
}
