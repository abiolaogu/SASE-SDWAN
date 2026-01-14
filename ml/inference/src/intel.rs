//! Threat Intelligence Integration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Threat Intelligence Manager
pub struct ThreatIntelManager {
    /// IOC database
    iocs: Arc<RwLock<IocDatabase>>,
    /// Feed configurations
    feeds: Arc<RwLock<Vec<ThreatFeed>>>,
}

impl ThreatIntelManager {
    pub fn new() -> Self {
        Self {
            iocs: Arc::new(RwLock::new(IocDatabase::new())),
            feeds: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add threat feed
    pub fn add_feed(&self, feed: ThreatFeed) {
        tracing::info!("Adding threat feed: {}", feed.name);
        self.feeds.write().push(feed);
    }

    /// Check IOC match
    pub fn check_ioc(&self, ioc_type: IocType, value: &str) -> Option<IocMatch> {
        self.iocs.read().lookup(ioc_type, value)
    }

    /// Enrich alert with threat intel
    pub fn enrich(&self, entities: &[crate::alerts::Entity]) -> Vec<ThreatContext> {
        let mut context = Vec::new();
        let iocs = self.iocs.read();
        
        for entity in entities {
            let ioc_type = match entity.entity_type {
                crate::alerts::EntityType::Ip => IocType::Ip,
                crate::alerts::EntityType::Domain => IocType::Domain,
                _ => continue,
            };
            
            if let Some(m) = iocs.lookup(ioc_type, &entity.value) {
                context.push(ThreatContext {
                    entity: entity.value.clone(),
                    threat_type: m.threat_type.clone(),
                    confidence: m.confidence,
                    source: m.source.clone(),
                    first_seen: m.first_seen,
                    last_seen: m.last_seen,
                    tags: m.tags.clone(),
                });
            }
        }
        
        context
    }

    /// Ingest STIX bundle
    pub async fn ingest_stix(&self, bundle: &StixBundle) -> Result<usize, String> {
        tracing::info!("Ingesting STIX bundle with {} objects", bundle.objects.len());
        
        let mut count = 0;
        for obj in &bundle.objects {
            if let Some(ioc) = self.stix_to_ioc(obj) {
                self.iocs.write().add(ioc);
                count += 1;
            }
        }
        
        Ok(count)
    }

    fn stix_to_ioc(&self, obj: &StixObject) -> Option<Ioc> {
        match obj.object_type.as_str() {
            "indicator" => {
                let pattern = obj.pattern.as_ref()?;
                let (ioc_type, value) = self.parse_stix_pattern(pattern)?;
                Some(Ioc {
                    ioc_type,
                    value,
                    threat_type: obj.labels.first().cloned().unwrap_or_default(),
                    confidence: obj.confidence.unwrap_or(50) as f64 / 100.0,
                    source: "STIX".into(),
                    first_seen: 0,
                    last_seen: 0,
                    tags: obj.labels.clone(),
                })
            }
            _ => None,
        }
    }

    fn parse_stix_pattern(&self, pattern: &str) -> Option<(IocType, String)> {
        // Simplified STIX pattern parsing
        if pattern.contains("ipv4-addr") {
            let value = pattern.split('\'').nth(1)?;
            Some((IocType::Ip, value.to_string()))
        } else if pattern.contains("domain-name") {
            let value = pattern.split('\'').nth(1)?;
            Some((IocType::Domain, value.to_string()))
        } else {
            None
        }
    }
}

impl Default for ThreatIntelManager {
    fn default() -> Self { Self::new() }
}

/// IOC database
struct IocDatabase {
    ips: HashMap<String, Ioc>,
    domains: HashMap<String, Ioc>,
    hashes: HashMap<String, Ioc>,
}

impl IocDatabase {
    fn new() -> Self {
        Self {
            ips: HashMap::new(),
            domains: HashMap::new(),
            hashes: HashMap::new(),
        }
    }

    fn add(&mut self, ioc: Ioc) {
        match ioc.ioc_type {
            IocType::Ip => { self.ips.insert(ioc.value.clone(), ioc); }
            IocType::Domain => { self.domains.insert(ioc.value.clone(), ioc); }
            IocType::Hash => { self.hashes.insert(ioc.value.clone(), ioc); }
            _ => {}
        }
    }

    fn lookup(&self, ioc_type: IocType, value: &str) -> Option<IocMatch> {
        let ioc = match ioc_type {
            IocType::Ip => self.ips.get(value),
            IocType::Domain => self.domains.get(value),
            IocType::Hash => self.hashes.get(value),
            _ => None,
        }?;

        Some(IocMatch {
            ioc_type: ioc.ioc_type,
            value: ioc.value.clone(),
            threat_type: ioc.threat_type.clone(),
            confidence: ioc.confidence,
            source: ioc.source.clone(),
            first_seen: ioc.first_seen,
            last_seen: ioc.last_seen,
            tags: ioc.tags.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Hash,
    Email,
}

#[derive(Debug, Clone)]
struct Ioc {
    ioc_type: IocType,
    value: String,
    threat_type: String,
    confidence: f64,
    source: String,
    first_seen: u64,
    last_seen: u64,
    tags: Vec<String>,
}

/// IOC match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub ioc_type: IocType,
    pub value: String,
    pub threat_type: String,
    pub confidence: f64,
    pub source: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub tags: Vec<String>,
}

/// Threat context for enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub entity: String,
    pub threat_type: String,
    pub confidence: f64,
    pub source: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub tags: Vec<String>,
}

/// Threat feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub feed_type: FeedType,
    pub url: String,
    pub api_key: Option<String>,
    pub refresh_hours: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FeedType {
    StixTaxii,
    Csv,
    Json,
}

/// STIX bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    pub objects: Vec<StixObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixObject {
    pub object_type: String,
    pub pattern: Option<String>,
    pub labels: Vec<String>,
    pub confidence: Option<u32>,
}
