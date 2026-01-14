//! Feed Aggregator
//!
//! Multi-source threat intelligence feed aggregation.

use crate::{FeedConfig, FeedType, FeedStatus, FeedHealth, Indicator, IocType, Confidence, Reliability, IntelSource};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

/// Feed aggregator for multiple intelligence sources
pub struct FeedAggregator {
    /// Configured feeds
    feeds: dashmap::DashMap<String, FeedConfig>,
    /// Feed status
    status: dashmap::DashMap<String, FeedStatus>,
    /// Indicator output channel
    indicator_tx: Option<mpsc::Sender<Indicator>>,
    /// HTTP client
    client: reqwest::Client,
}

impl FeedAggregator {
    pub fn new() -> Self {
        Self {
            feeds: dashmap::DashMap::new(),
            status: dashmap::DashMap::new(),
            indicator_tx: None,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap(),
        }
    }
    
    /// Add a new feed
    pub fn add_feed(&self, config: FeedConfig) {
        let status = FeedStatus {
            feed_id: config.id.clone(),
            ..Default::default()
        };
        
        self.status.insert(config.id.clone(), status);
        self.feeds.insert(config.id.clone(), config);
    }
    
    /// Remove a feed
    pub fn remove_feed(&self, feed_id: &str) {
        self.feeds.remove(feed_id);
        self.status.remove(feed_id);
    }
    
    /// Get feed status
    pub fn get_status(&self, feed_id: &str) -> Option<FeedStatus> {
        self.status.get(feed_id).map(|s| s.clone())
    }
    
    /// Get all feed statuses
    pub fn get_all_status(&self) -> Vec<FeedStatus> {
        self.status.iter().map(|s| s.clone()).collect()
    }
    
    /// Poll a specific feed
    pub async fn poll_feed(&self, feed_id: &str) -> Result<Vec<Indicator>, FeedError> {
        let config = self.feeds.get(feed_id)
            .ok_or(FeedError::NotFound)?
            .clone();
        
        if !config.enabled {
            return Err(FeedError::Disabled);
        }
        
        let result = match config.feed_type {
            FeedType::StixTaxii => self.poll_stix_taxii(&config).await,
            FeedType::Misp => self.poll_misp(&config).await,
            FeedType::OpenCti => self.poll_opencti(&config).await,
            FeedType::CsvFile => self.poll_csv(&config).await,
            FeedType::JsonApi => self.poll_json(&config).await,
            FeedType::RssFeed => self.poll_rss(&config).await,
            FeedType::Custom => self.poll_custom(&config).await,
        };
        
        // Update status
        if let Some(mut status) = self.status.get_mut(feed_id) {
            status.last_poll = Some(chrono::Utc::now());
            status.next_poll = Some(chrono::Utc::now() + chrono::Duration::from_std(config.poll_interval).unwrap_or_default());
            
            match &result {
                Ok(indicators) => {
                    status.health = FeedHealth::Healthy;
                    status.indicators_total += indicators.len() as u64;
                    status.indicators_active += indicators.len() as u64;
                    status.last_error = None;
                }
                Err(e) => {
                    status.health = FeedHealth::Error;
                    status.last_error = Some(format!("{}", e));
                }
            }
        }
        
        result
    }
    
    /// Poll STIX/TAXII feed
    async fn poll_stix_taxii(&self, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
        info!("Polling STIX/TAXII feed: {}", config.name);
        
        let mut request = self.client.get(&config.url);
        
        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(FeedError::HttpError(response.status().as_u16()));
        }
        
        let body = response.text().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        // Parse STIX bundle
        crate::stix::parse_stix_bundle(&body, config)
    }
    
    /// Poll MISP feed
    async fn poll_misp(&self, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
        info!("Polling MISP feed: {}", config.name);
        
        let mut request = self.client.get(&config.url);
        
        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", api_key.clone());
        }
        
        request = request.header("Accept", "application/json");
        
        let response = request.send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body: serde_json::Value = response.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        parse_misp_response(&body, config)
    }
    
    /// Poll OpenCTI feed
    async fn poll_opencti(&self, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
        info!("Polling OpenCTI feed: {}", config.name);
        
        // OpenCTI uses GraphQL
        let query = r#"{
            indicators(first: 1000) {
                edges {
                    node {
                        id
                        pattern
                        valid_from
                        valid_until
                        confidence
                        objectLabel {
                            edges {
                                node {
                                    value
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        
        let mut request = self.client.post(&config.url)
            .json(&serde_json::json!({ "query": query }));
        
        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body: serde_json::Value = response.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        parse_opencti_response(&body, config)
    }
    
    /// Poll CSV file feed
    async fn poll_csv(&self, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
        info!("Polling CSV feed: {}", config.name);
        
        let response = self.client.get(&config.url).send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body = response.text().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        parse_csv_feed(&body, config)
    }
    
    /// Poll JSON API feed
    async fn poll_json(&self, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
        info!("Polling JSON API feed: {}", config.name);
        
        let mut request = self.client.get(&config.url);
        
        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body: serde_json::Value = response.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        parse_json_feed(&body, config)
    }
    
    /// Poll RSS feed
    async fn poll_rss(&self, _config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
        // RSS feeds typically contain threat reports, not raw IoCs
        Ok(Vec::new())
    }
    
    /// Poll custom feed
    async fn poll_custom(&self, _config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
        Ok(Vec::new())
    }
}

impl Default for FeedAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum FeedError {
    NotFound,
    Disabled,
    Network(String),
    HttpError(u16),
    Parse(String),
    Timeout,
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Feed not found"),
            Self::Disabled => write!(f, "Feed is disabled"),
            Self::Network(e) => write!(f, "Network error: {}", e),
            Self::HttpError(code) => write!(f, "HTTP error: {}", code),
            Self::Parse(e) => write!(f, "Parse error: {}", e),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}

/// Parse MISP response
fn parse_misp_response(json: &serde_json::Value, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
    let mut indicators = Vec::new();
    
    if let Some(events) = json.get("response").and_then(|r| r.as_array()) {
        for event in events {
            if let Some(attrs) = event.get("Attribute").and_then(|a| a.as_array()) {
                for attr in attrs {
                    if let Some(indicator) = parse_misp_attribute(attr, config) {
                        indicators.push(indicator);
                    }
                }
            }
        }
    }
    
    Ok(indicators)
}

fn parse_misp_attribute(attr: &serde_json::Value, config: &FeedConfig) -> Option<Indicator> {
    let value = attr.get("value")?.as_str()?;
    let attr_type = attr.get("type")?.as_str()?;
    
    let ioc_type = match attr_type {
        "ip-src" | "ip-dst" => IocType::IPv4,
        "domain" | "hostname" => IocType::Domain,
        "url" => IocType::Url,
        "md5" => IocType::FileHashMd5,
        "sha1" => IocType::FileHashSha1,
        "sha256" => IocType::FileHashSha256,
        "email-src" | "email-dst" => IocType::Email,
        _ => return None,
    };
    
    Some(Indicator {
        id: attr.get("uuid").and_then(|u| u.as_str()).unwrap_or("unknown").to_string(),
        ioc_type,
        value: value.to_string(),
        confidence: config.default_confidence,
        severity: crate::Severity::Medium,
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        expires_at: None,
        sources: vec![IntelSource {
            name: config.name.clone(),
            feed_id: config.id.clone(),
            reliability: config.reliability,
            timestamp: chrono::Utc::now(),
            reference_url: None,
        }],
        tags: config.tags.clone(),
        context: crate::IocContext::default(),
        mitre_tactics: Vec::new(),
        mitre_techniques: Vec::new(),
        related_iocs: Vec::new(),
    })
}

/// Parse OpenCTI response
fn parse_opencti_response(json: &serde_json::Value, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
    let mut indicators = Vec::new();
    
    if let Some(edges) = json
        .get("data")
        .and_then(|d| d.get("indicators"))
        .and_then(|i| i.get("edges"))
        .and_then(|e| e.as_array())
    {
        for edge in edges {
            if let Some(node) = edge.get("node") {
                if let Some(indicator) = parse_opencti_indicator(node, config) {
                    indicators.push(indicator);
                }
            }
        }
    }
    
    Ok(indicators)
}

fn parse_opencti_indicator(node: &serde_json::Value, config: &FeedConfig) -> Option<Indicator> {
    let pattern = node.get("pattern")?.as_str()?;
    let (ioc_type, value) = parse_stix_pattern(pattern)?;
    
    Some(Indicator {
        id: node.get("id").and_then(|i| i.as_str()).unwrap_or("unknown").to_string(),
        ioc_type,
        value,
        confidence: config.default_confidence,
        severity: crate::Severity::Medium,
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        expires_at: None,
        sources: vec![IntelSource {
            name: config.name.clone(),
            feed_id: config.id.clone(),
            reliability: config.reliability,
            timestamp: chrono::Utc::now(),
            reference_url: None,
        }],
        tags: config.tags.clone(),
        context: crate::IocContext::default(),
        mitre_tactics: Vec::new(),
        mitre_techniques: Vec::new(),
        related_iocs: Vec::new(),
    })
}

/// Parse STIX pattern like [ipv4-addr:value = '1.2.3.4']
fn parse_stix_pattern(pattern: &str) -> Option<(IocType, String)> {
    // Simple regex-based parsing
    let re = regex::Regex::new(r"\[(\w+(?:-\w+)?):(\w+)\s*=\s*'([^']+)'\]").ok()?;
    
    let caps = re.captures(pattern)?;
    let obj_type = caps.get(1)?.as_str();
    let value = caps.get(3)?.as_str();
    
    let ioc_type = match obj_type {
        "ipv4-addr" => IocType::IPv4,
        "ipv6-addr" => IocType::IPv6,
        "domain-name" => IocType::Domain,
        "url" => IocType::Url,
        "file" => IocType::FileHashSha256, // Simplified
        "email-addr" => IocType::Email,
        _ => return None,
    };
    
    Some((ioc_type, value.to_string()))
}

/// Parse CSV feed
fn parse_csv_feed(csv: &str, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
    let mut indicators = Vec::new();
    
    for line in csv.lines().skip(1) { // Skip header
        let parts: Vec<&str> = line.split(',').collect();
        if parts.is_empty() {
            continue;
        }
        
        let value = parts[0].trim().trim_matches('"');
        
        // Auto-detect type
        if let Some(ioc_type) = detect_ioc_type(value) {
            indicators.push(Indicator {
                id: uuid::Uuid::new_v4().to_string(),
                ioc_type,
                value: value.to_string(),
                confidence: config.default_confidence,
                severity: crate::Severity::Medium,
                first_seen: chrono::Utc::now(),
                last_seen: chrono::Utc::now(),
                expires_at: None,
                sources: vec![IntelSource {
                    name: config.name.clone(),
                    feed_id: config.id.clone(),
                    reliability: config.reliability,
                    timestamp: chrono::Utc::now(),
                    reference_url: None,
                }],
                tags: config.tags.clone(),
                context: crate::IocContext::default(),
                mitre_tactics: Vec::new(),
                mitre_techniques: Vec::new(),
                related_iocs: Vec::new(),
            });
        }
    }
    
    Ok(indicators)
}

/// Parse generic JSON feed
fn parse_json_feed(json: &serde_json::Value, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
    let mut indicators = Vec::new();
    
    // Try common JSON structures
    let items = json.as_array()
        .or_else(|| json.get("data").and_then(|d| d.as_array()))
        .or_else(|| json.get("indicators").and_then(|i| i.as_array()))
        .or_else(|| json.get("iocs").and_then(|i| i.as_array()));
    
    if let Some(items) = items {
        for item in items {
            // Try to extract value from common field names
            let value = item.get("value")
                .or_else(|| item.get("indicator"))
                .or_else(|| item.get("ioc"))
                .and_then(|v| v.as_str());
            
            if let Some(value) = value {
                if let Some(ioc_type) = detect_ioc_type(value) {
                    indicators.push(Indicator {
                        id: item.get("id")
                            .and_then(|i| i.as_str())
                            .unwrap_or(&uuid::Uuid::new_v4().to_string())
                            .to_string(),
                        ioc_type,
                        value: value.to_string(),
                        confidence: config.default_confidence,
                        severity: crate::Severity::Medium,
                        first_seen: chrono::Utc::now(),
                        last_seen: chrono::Utc::now(),
                        expires_at: None,
                        sources: vec![IntelSource {
                            name: config.name.clone(),
                            feed_id: config.id.clone(),
                            reliability: config.reliability,
                            timestamp: chrono::Utc::now(),
                            reference_url: None,
                        }],
                        tags: config.tags.clone(),
                        context: crate::IocContext::default(),
                        mitre_tactics: Vec::new(),
                        mitre_techniques: Vec::new(),
                        related_iocs: Vec::new(),
                    });
                }
            }
        }
    }
    
    Ok(indicators)
}

/// Auto-detect IoC type from value
fn detect_ioc_type(value: &str) -> Option<IocType> {
    // IPv4
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(IocType::IPv4);
    }
    
    // IPv6
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(IocType::IPv6);
    }
    
    // URL
    if value.starts_with("http://") || value.starts_with("https://") {
        return Some(IocType::Url);
    }
    
    // Email
    if value.contains('@') && value.contains('.') {
        return Some(IocType::Email);
    }
    
    // Hash detection by length
    let hex_chars = value.chars().all(|c| c.is_ascii_hexdigit());
    if hex_chars {
        match value.len() {
            32 => return Some(IocType::FileHashMd5),
            40 => return Some(IocType::FileHashSha1),
            64 => return Some(IocType::FileHashSha256),
            _ => {}
        }
    }
    
    // CVE
    if value.starts_with("CVE-") {
        return Some(IocType::Cve);
    }
    
    // Domain (default for non-matching strings that look like domains)
    if value.contains('.') && !value.contains('/') && !value.contains(' ') {
        return Some(IocType::Domain);
    }
    
    None
}

/// Pre-configured feed sources
pub fn default_feeds() -> Vec<FeedConfig> {
    vec![
        FeedConfig {
            id: "abuse-ch-urlhaus".to_string(),
            name: "URLhaus".to_string(),
            feed_type: FeedType::CsvFile,
            url: "https://urlhaus.abuse.ch/downloads/csv/".to_string(),
            api_key: None,
            poll_interval: std::time::Duration::from_secs(3600),
            enabled: true,
            reliability: Reliability::B,
            default_confidence: Confidence::High,
            ioc_types: vec![IocType::Url],
            tags: vec!["malware".to_string(), "urlhaus".to_string()],
        },
        FeedConfig {
            id: "abuse-ch-feodo".to_string(),
            name: "Feodo Tracker".to_string(),
            feed_type: FeedType::CsvFile,
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv".to_string(),
            api_key: None,
            poll_interval: std::time::Duration::from_secs(3600),
            enabled: true,
            reliability: Reliability::A,
            default_confidence: Confidence::Confirmed,
            ioc_types: vec![IocType::IPv4],
            tags: vec!["botnet".to_string(), "c2".to_string(), "feodo".to_string()],
        },
        FeedConfig {
            id: "abuse-ch-ssl-bl".to_string(),
            name: "SSL Blacklist".to_string(),
            feed_type: FeedType::CsvFile,
            url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv".to_string(),
            api_key: None,
            poll_interval: std::time::Duration::from_secs(3600),
            enabled: true,
            reliability: Reliability::A,
            default_confidence: Confidence::High,
            ioc_types: vec![IocType::IPv4],
            tags: vec!["ssl".to_string(), "c2".to_string()],
        },
    ]
}
