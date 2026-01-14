//! Event Enrichment
//!
//! Add context from threat intel, asset DB, user directory.

use crate::{SecurityEvent, Indicator, IndicatorType, ThreatIntelMatch, AssetInfo, UserInfo};

pub struct EventEnricher {
    threat_intel: ThreatIntelEnricher,
    asset_db: AssetEnricher,
    user_dir: UserEnricher,
    geo_ip: GeoIpEnricher,
}

impl EventEnricher {
    pub fn new() -> Self {
        Self {
            threat_intel: ThreatIntelEnricher::new(),
            asset_db: AssetEnricher::new(),
            user_dir: UserEnricher::new(),
            geo_ip: GeoIpEnricher::new(),
        }
    }
    
    pub async fn enrich(&self, event: &mut SecurityEvent) -> EnrichmentResult {
        let mut result = EnrichmentResult::default();
        
        // Threat intel enrichment
        for indicator in &event.indicators {
            if let Some(intel) = self.threat_intel.lookup(indicator).await {
                result.threat_intel.push(intel);
            }
        }
        
        // Asset enrichment
        if let Some(ip) = &event.source.ip {
            if let Some(asset) = self.asset_db.lookup_by_ip(ip).await {
                result.asset = Some(asset);
            }
        }
        if let Some(host) = &event.source.host {
            if let Some(asset) = self.asset_db.lookup_by_hostname(host).await {
                result.asset = Some(asset);
            }
        }
        
        // GeoIP enrichment
        if let Some(ip) = &event.source.ip {
            if let Some(geo) = self.geo_ip.lookup(ip).await {
                result.geo = Some(geo);
            }
        }
        
        // Add enrichment tags
        if !result.threat_intel.is_empty() {
            event.tags.push("threat_intel_match".to_string());
        }
        if result.asset.is_some() {
            event.tags.push("known_asset".to_string());
        }
        
        result
    }
}

impl Default for EventEnricher {
    fn default() -> Self { Self::new() }
}

#[derive(Default, Clone)]
pub struct EnrichmentResult {
    pub threat_intel: Vec<ThreatIntelMatch>,
    pub asset: Option<AssetInfo>,
    pub user: Option<UserInfo>,
    pub geo: Option<GeoInfo>,
}

#[derive(Clone, serde::Serialize)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

// Threat Intel Enricher
struct ThreatIntelEnricher {
    cache: dashmap::DashMap<String, ThreatIntelMatch>,
}

impl ThreatIntelEnricher {
    fn new() -> Self {
        Self { cache: dashmap::DashMap::new() }
    }
    
    async fn lookup(&self, indicator: &Indicator) -> Option<ThreatIntelMatch> {
        // Check cache
        if let Some(cached) = self.cache.get(&indicator.value) {
            return Some(cached.clone());
        }
        
        // Query threat intel feeds (placeholder)
        // In production: query OTX, AbuseIPDB, VirusTotal, etc.
        None
    }
}

// Asset Enricher
struct AssetEnricher {
    assets_by_ip: dashmap::DashMap<String, AssetInfo>,
    assets_by_hostname: dashmap::DashMap<String, AssetInfo>,
}

impl AssetEnricher {
    fn new() -> Self {
        Self {
            assets_by_ip: dashmap::DashMap::new(),
            assets_by_hostname: dashmap::DashMap::new(),
        }
    }
    
    async fn lookup_by_ip(&self, ip: &str) -> Option<AssetInfo> {
        self.assets_by_ip.get(ip).map(|a| a.clone())
    }
    
    async fn lookup_by_hostname(&self, hostname: &str) -> Option<AssetInfo> {
        self.assets_by_hostname.get(hostname).map(|a| a.clone())
    }
    
    pub fn register_asset(&self, asset: AssetInfo, ip: Option<&str>, hostname: Option<&str>) {
        if let Some(ip) = ip {
            self.assets_by_ip.insert(ip.to_string(), asset.clone());
        }
        if let Some(hostname) = hostname {
            self.assets_by_hostname.insert(hostname.to_string(), asset);
        }
    }
}

// User Enricher
struct UserEnricher {
    users: dashmap::DashMap<String, UserInfo>,
}

impl UserEnricher {
    fn new() -> Self {
        Self { users: dashmap::DashMap::new() }
    }
    
    async fn lookup(&self, username: &str) -> Option<UserInfo> {
        self.users.get(username).map(|u| u.clone())
    }
}

// GeoIP Enricher
struct GeoIpEnricher {
    // In production: MaxMind GeoIP database
}

impl GeoIpEnricher {
    fn new() -> Self { Self {} }
    
    async fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        // Placeholder - in production use MaxMind
        if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") {
            Some(GeoInfo {
                country: "Private".to_string(),
                country_code: "XX".to_string(),
                city: None,
                latitude: 0.0,
                longitude: 0.0,
                asn: None,
                org: Some("Private Network".to_string()),
            })
        } else {
            None
        }
    }
}
