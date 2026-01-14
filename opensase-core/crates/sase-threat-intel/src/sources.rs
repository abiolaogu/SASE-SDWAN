//! External Threat Intelligence Sources
//!
//! Additional feed integrations for AlienVault OTX, VirusTotal, etc.

use crate::{Indicator, IocType, Confidence, Severity, IntelSource, IocContext, ThreatType, Reliability};
use crate::feeds::FeedError;

// =============================================================================
// AlienVault OTX Client
// =============================================================================

/// AlienVault Open Threat Exchange (OTX) client
pub struct OtxClient {
    api_key: String,
    client: reqwest::Client,
    base_url: String,
}

impl OtxClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
            base_url: "https://otx.alienvault.com/api/v1".to_string(),
        }
    }
    
    /// Get subscribed pulses (threat reports)
    pub async fn get_subscribed_pulses(&self, limit: u32) -> Result<Vec<OtxPulse>, FeedError> {
        let url = format!("{}/pulses/subscribed?limit={}", self.base_url, limit);
        
        let resp = self.client.get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body: OtxPulsesResponse = resp.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        Ok(body.results)
    }
    
    /// Get pulse details with indicators
    pub async fn get_pulse(&self, pulse_id: &str) -> Result<OtxPulse, FeedError> {
        let url = format!("{}/pulses/{}", self.base_url, pulse_id);
        
        let resp = self.client.get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let pulse: OtxPulse = resp.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        Ok(pulse)
    }
    
    /// Get indicators for an IP
    pub async fn get_ip_indicators(&self, ip: &str) -> Result<OtxIpIndicator, FeedError> {
        let url = format!("{}/indicators/IPv4/{}/general", self.base_url, ip);
        
        let resp = self.client.get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        resp.json().await.map_err(|e| FeedError::Parse(e.to_string()))
    }
    
    /// Get indicators for a domain
    pub async fn get_domain_indicators(&self, domain: &str) -> Result<OtxDomainIndicator, FeedError> {
        let url = format!("{}/indicators/domain/{}/general", self.base_url, domain);
        
        let resp = self.client.get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        resp.json().await.map_err(|e| FeedError::Parse(e.to_string()))
    }
    
    /// Convert OTX pulse to internal indicators
    pub fn pulse_to_indicators(&self, pulse: &OtxPulse) -> Vec<Indicator> {
        let mut indicators = Vec::new();
        
        for ioc in &pulse.indicators {
            if let Some(indicator) = self.otx_indicator_to_internal(ioc, pulse) {
                indicators.push(indicator);
            }
        }
        
        indicators
    }
    
    fn otx_indicator_to_internal(&self, ioc: &OtxIndicator, pulse: &OtxPulse) -> Option<Indicator> {
        let ioc_type = match ioc.indicator_type.as_str() {
            "IPv4" => IocType::IPv4,
            "IPv6" => IocType::IPv6,
            "domain" | "hostname" => IocType::Domain,
            "URL" | "URI" => IocType::Url,
            "FileHash-MD5" => IocType::FileHashMd5,
            "FileHash-SHA1" => IocType::FileHashSha1,
            "FileHash-SHA256" => IocType::FileHashSha256,
            "email" => IocType::Email,
            "CVE" => IocType::Cve,
            "YARA" | "Mutex" => return None, // Skip unsupported types
            _ => return None,
        };
        
        Some(Indicator {
            id: format!("otx-{}-{}", pulse.id, ioc.id),
            ioc_type,
            value: ioc.indicator.clone(),
            confidence: Confidence::Medium,
            severity: Severity::Medium,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            expires_at: None,
            sources: vec![IntelSource {
                name: "AlienVault OTX".to_string(),
                feed_id: format!("otx-{}", pulse.id),
                reliability: Reliability::B,
                timestamp: chrono::Utc::now(),
                reference_url: Some(format!("https://otx.alienvault.com/pulse/{}", pulse.id)),
            }],
            tags: pulse.tags.clone(),
            context: IocContext {
                description: ioc.description.clone(),
                ..Default::default()
            },
            mitre_tactics: Vec::new(),
            mitre_techniques: pulse.attack_ids.clone().unwrap_or_default(),
            related_iocs: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OtxPulsesResponse {
    pub results: Vec<OtxPulse>,
    pub count: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OtxPulse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub author_name: String,
    pub created: String,
    pub modified: String,
    pub tags: Vec<String>,
    pub targeted_countries: Option<Vec<String>>,
    pub malware_families: Option<Vec<String>>,
    pub attack_ids: Option<Vec<String>>,
    pub indicators: Vec<OtxIndicator>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OtxIndicator {
    pub id: u64,
    #[serde(rename = "type")]
    pub indicator_type: String,
    pub indicator: String,
    pub description: Option<String>,
    pub created: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OtxIpIndicator {
    pub indicator: String,
    pub pulse_info: OtxPulseInfo,
    pub country_name: Option<String>,
    pub country_code: Option<String>,
    pub asn: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OtxDomainIndicator {
    pub indicator: String,
    pub pulse_info: OtxPulseInfo,
    pub whois: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OtxPulseInfo {
    pub count: u32,
    pub pulses: Vec<OtxPulseSummary>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OtxPulseSummary {
    pub id: String,
    pub name: String,
}

// =============================================================================
// VirusTotal Integration
// =============================================================================

/// VirusTotal API client
pub struct VirusTotalClient {
    api_key: String,
    client: reqwest::Client,
    base_url: String,
}

impl VirusTotalClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
            base_url: "https://www.virustotal.com/api/v3".to_string(),
        }
    }
    
    /// Lookup IP address
    pub async fn lookup_ip(&self, ip: &str) -> Result<VtIpReport, FeedError> {
        let url = format!("{}/ip_addresses/{}", self.base_url, ip);
        
        let resp = self.client.get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        resp.json().await.map_err(|e| FeedError::Parse(e.to_string()))
    }
    
    /// Lookup domain
    pub async fn lookup_domain(&self, domain: &str) -> Result<VtDomainReport, FeedError> {
        let url = format!("{}/domains/{}", self.base_url, domain);
        
        let resp = self.client.get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        resp.json().await.map_err(|e| FeedError::Parse(e.to_string()))
    }
    
    /// Lookup file hash
    pub async fn lookup_file(&self, hash: &str) -> Result<VtFileReport, FeedError> {
        let url = format!("{}/files/{}", self.base_url, hash);
        
        let resp = self.client.get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        resp.json().await.map_err(|e| FeedError::Parse(e.to_string()))
    }
    
    /// Lookup URL
    pub async fn lookup_url(&self, url: &str) -> Result<VtUrlReport, FeedError> {
        use base64::Engine;
        let url_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url);
        let api_url = format!("{}/urls/{}", self.base_url, url_id);
        
        let resp = self.client.get(&api_url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        resp.json().await.map_err(|e| FeedError::Parse(e.to_string()))
    }
    
    /// Calculate reputation score from analysis stats
    pub fn calculate_reputation(&self, stats: &VtAnalysisStats) -> i32 {
        let total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
        if total == 0 {
            return 0;
        }
        
        let malicious_ratio = (stats.malicious as f64) / (total as f64);
        let suspicious_ratio = (stats.suspicious as f64) / (total as f64);
        
        // Score from -100 (very bad) to 100 (very good)
        ((1.0 - malicious_ratio - suspicious_ratio * 0.5) * 200.0 - 100.0) as i32
    }
    
    /// Determine severity from analysis stats
    pub fn determine_severity(&self, stats: &VtAnalysisStats) -> Severity {
        if stats.malicious >= 10 {
            Severity::Critical
        } else if stats.malicious >= 5 {
            Severity::High
        } else if stats.malicious >= 1 || stats.suspicious >= 5 {
            Severity::Medium
        } else if stats.suspicious >= 1 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtIpReport {
    pub data: VtIpData,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtIpData {
    pub id: String,
    pub attributes: VtIpAttributes,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtIpAttributes {
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub as_owner: Option<String>,
    pub last_analysis_stats: VtAnalysisStats,
    pub reputation: Option<i32>,
    pub total_votes: Option<VtVotes>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtDomainReport {
    pub data: VtDomainData,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtDomainData {
    pub id: String,
    pub attributes: VtDomainAttributes,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtDomainAttributes {
    pub last_analysis_stats: VtAnalysisStats,
    pub reputation: Option<i32>,
    pub registrar: Option<String>,
    pub creation_date: Option<i64>,
    pub categories: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtFileReport {
    pub data: VtFileData,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtFileData {
    pub id: String,
    pub attributes: VtFileAttributes,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtFileAttributes {
    pub last_analysis_stats: VtAnalysisStats,
    pub reputation: Option<i32>,
    pub type_description: Option<String>,
    pub meaningful_name: Option<String>,
    pub popular_threat_classification: Option<VtThreatClassification>,
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtThreatClassification {
    pub suggested_threat_label: Option<String>,
    pub popular_threat_category: Option<Vec<VtPopularCategory>>,
    pub popular_threat_name: Option<Vec<VtPopularName>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtPopularCategory {
    pub value: String,
    pub count: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtPopularName {
    pub value: String,
    pub count: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtUrlReport {
    pub data: VtUrlData,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtUrlData {
    pub id: String,
    pub attributes: VtUrlAttributes,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtUrlAttributes {
    pub last_analysis_stats: VtAnalysisStats,
    pub reputation: Option<i32>,
    pub categories: Option<std::collections::HashMap<String, String>>,
    pub last_final_url: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct VtAnalysisStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    #[serde(default)]
    pub timeout: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VtVotes {
    pub harmless: u32,
    pub malicious: u32,
}

// =============================================================================
// AbuseIPDB Integration
// =============================================================================

/// AbuseIPDB API client
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
    
    /// Check IP reputation
    pub async fn check(&self, ip: &str) -> Result<AbuseIpDbReport, FeedError> {
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );
        
        let resp = self.client.get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        resp.json().await.map_err(|e| FeedError::Parse(e.to_string()))
    }
    
    /// Get blacklist
    pub async fn get_blacklist(&self, confidence_minimum: u32) -> Result<Vec<AbuseIpDbEntry>, FeedError> {
        let url = format!(
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={}",
            confidence_minimum
        );
        
        let resp = self.client.get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body: AbuseIpDbBlacklist = resp.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        Ok(body.data)
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
    pub is_public: bool,
    pub abuse_confidence_score: u32,
    pub country_code: Option<String>,
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub total_reports: u32,
    pub num_distinct_users: u32,
    pub last_reported_at: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AbuseIpDbBlacklist {
    pub data: Vec<AbuseIpDbEntry>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseIpDbEntry {
    pub ip_address: String,
    pub abuse_confidence_score: u32,
    pub country_code: Option<String>,
}

impl AbuseIpDbData {
    /// Convert to internal indicator
    pub fn to_indicator(&self) -> Option<Indicator> {
        if self.abuse_confidence_score < 25 {
            return None;
        }
        
        let confidence = if self.abuse_confidence_score >= 90 {
            Confidence::Confirmed
        } else if self.abuse_confidence_score >= 70 {
            Confidence::High
        } else if self.abuse_confidence_score >= 50 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        
        let severity = if self.abuse_confidence_score >= 90 {
            Severity::Critical
        } else if self.abuse_confidence_score >= 70 {
            Severity::High
        } else {
            Severity::Medium
        };
        
        Some(Indicator {
            id: format!("abuseipdb-{}", self.ip_address),
            ioc_type: IocType::IPv4,
            value: self.ip_address.clone(),
            confidence,
            severity,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            expires_at: None,
            sources: vec![IntelSource {
                name: "AbuseIPDB".to_string(),
                feed_id: "abuseipdb".to_string(),
                reliability: Reliability::A,
                timestamp: chrono::Utc::now(),
                reference_url: Some(format!("https://www.abuseipdb.com/check/{}", self.ip_address)),
            }],
            tags: vec!["abuse".to_string()],
            context: IocContext {
                geo_location: self.country_code.as_ref().map(|cc| crate::GeoLocation {
                    country: cc.clone(),
                    country_code: cc.clone(),
                    city: None,
                    asn: None,
                    as_org: self.isp.clone(),
                }),
                description: self.usage_type.clone(),
                ..Default::default()
            },
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            related_iocs: Vec::new(),
        })
    }
}
