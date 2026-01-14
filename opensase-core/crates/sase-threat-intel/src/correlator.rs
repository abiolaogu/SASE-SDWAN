//! IoC Correlation Engine
//!
//! Correlates indicators across sources and identifies relationships.

use crate::{Indicator, IocType, IocId, Confidence, Severity};
use std::collections::{HashMap, HashSet};

/// IoC correlation engine
pub struct Correlator {
    /// Domain to IP mappings
    domain_ips: dashmap::DashMap<String, HashSet<String>>,
    /// IP to domain mappings
    ip_domains: dashmap::DashMap<String, HashSet<String>>,
    /// Hash relationships (different hash types for same file)
    hash_relations: dashmap::DashMap<String, HashSet<String>>,
    /// Campaign groupings
    campaigns: dashmap::DashMap<String, CampaignInfo>,
    /// Correlation rules
    rules: Vec<CorrelationRule>,
}

#[derive(Debug, Clone)]
pub struct CampaignInfo {
    pub name: String,
    pub indicators: HashSet<IocId>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub tags: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub name: String,
    pub description: String,
    pub conditions: Vec<CorrelationCondition>,
    pub action: CorrelationAction,
}

#[derive(Debug, Clone)]
pub enum CorrelationCondition {
    /// Same source IP within time window
    SameSourceIp { window_secs: u64 },
    /// Same domain within time window
    SameDomain { window_secs: u64 },
    /// Multiple IoC types for same entity
    MultipleTypes { min_types: usize },
    /// Multiple sources confirm same IoC
    MultipleSourcesConfirm { min_sources: usize },
    /// Associated with known campaign
    KnownCampaign,
    /// High confidence from reliable source
    HighConfidenceSource,
}

#[derive(Debug, Clone)]
pub enum CorrelationAction {
    /// Increase confidence score
    BoostConfidence(i32),
    /// Increase severity
    BoostSeverity,
    /// Link to campaign
    LinkToCampaign(String),
    /// Add tag
    AddTag(String),
    /// Create alert
    CreateAlert,
}

/// Correlation result
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub indicator_id: IocId,
    pub related_indicators: Vec<IocId>,
    pub confidence_boost: i32,
    pub severity_boost: bool,
    pub new_tags: Vec<String>,
    pub campaign: Option<String>,
    pub correlations: Vec<CorrelationMatch>,
}

#[derive(Debug, Clone)]
pub struct CorrelationMatch {
    pub rule_name: String,
    pub matched_indicators: Vec<IocId>,
    pub description: String,
}

impl Correlator {
    pub fn new() -> Self {
        Self {
            domain_ips: dashmap::DashMap::new(),
            ip_domains: dashmap::DashMap::new(),
            hash_relations: dashmap::DashMap::new(),
            campaigns: dashmap::DashMap::new(),
            rules: default_correlation_rules(),
        }
    }
    
    /// Correlate a new indicator
    pub fn correlate(&self, indicator: &Indicator) -> CorrelationResult {
        let mut result = CorrelationResult {
            indicator_id: indicator.id.clone(),
            related_indicators: Vec::new(),
            confidence_boost: 0,
            severity_boost: false,
            new_tags: Vec::new(),
            campaign: None,
            correlations: Vec::new(),
        };
        
        // Find related indicators by type
        match indicator.ioc_type {
            IocType::Domain => {
                // Check if we have IP mappings for this domain
                if let Some(ips) = self.domain_ips.get(&indicator.value) {
                    for ip in ips.iter() {
                        result.related_indicators.push(format!("ipv4:{}", ip));
                    }
                }
            }
            IocType::IPv4 | IocType::IPv6 => {
                // Check if we have domain mappings for this IP
                if let Some(domains) = self.ip_domains.get(&indicator.value) {
                    for domain in domains.iter() {
                        result.related_indicators.push(format!("domain:{}", domain));
                    }
                }
            }
            IocType::FileHashMd5 | IocType::FileHashSha1 | IocType::FileHashSha256 => {
                // Check for related hashes
                if let Some(related) = self.hash_relations.get(&indicator.value) {
                    for hash in related.iter() {
                        result.related_indicators.push(hash.clone());
                    }
                }
            }
            _ => {}
        }
        
        // Check multiple source confirmation
        if indicator.sources.len() >= 3 {
            result.confidence_boost += 25;
            result.correlations.push(CorrelationMatch {
                rule_name: "multi_source_confirm".to_string(),
                matched_indicators: vec![indicator.id.clone()],
                description: format!("Confirmed by {} sources", indicator.sources.len()),
            });
        }
        
        // Check campaign linkage
        for campaign in self.campaigns.iter() {
            if campaign.indicators.contains(&indicator.id) {
                result.campaign = Some(campaign.name.clone());
                result.new_tags.push(format!("campaign:{}", campaign.name));
                break;
            }
            
            // Check tag overlap
            let indicator_tags: HashSet<_> = indicator.tags.iter().cloned().collect();
            let overlap: HashSet<_> = indicator_tags.intersection(&campaign.tags).collect();
            if overlap.len() >= 2 {
                result.campaign = Some(campaign.name.clone());
                result.new_tags.push(format!("campaign:{}", campaign.name));
                break;
            }
        }
        
        result
    }
    
    /// Add domain-IP relationship
    pub fn add_domain_ip(&self, domain: &str, ip: &str) {
        self.domain_ips.entry(domain.to_lowercase())
            .or_default()
            .insert(ip.to_string());
        
        self.ip_domains.entry(ip.to_string())
            .or_default()
            .insert(domain.to_lowercase());
    }
    
    /// Add hash relationship
    pub fn add_hash_relation(&self, hash1: &str, hash2: &str) {
        self.hash_relations.entry(hash1.to_lowercase())
            .or_default()
            .insert(hash2.to_lowercase());
        
        self.hash_relations.entry(hash2.to_lowercase())
            .or_default()
            .insert(hash1.to_lowercase());
    }
    
    /// Register a campaign
    pub fn register_campaign(&self, name: &str, indicators: Vec<IocId>, tags: Vec<String>) {
        let campaign = CampaignInfo {
            name: name.to_string(),
            indicators: indicators.into_iter().collect(),
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            tags: tags.into_iter().collect(),
        };
        
        self.campaigns.insert(name.to_string(), campaign);
    }
    
    /// Get related indicators
    pub fn get_related(&self, indicator: &Indicator) -> Vec<IocId> {
        let result = self.correlate(indicator);
        result.related_indicators
    }
    
    /// Apply correlation result to indicator
    pub fn apply(&self, indicator: &mut Indicator, result: &CorrelationResult) {
        // Boost confidence
        if result.confidence_boost > 0 {
            let new_confidence = match indicator.confidence {
                Confidence::Unknown => Confidence::Low,
                Confidence::Low if result.confidence_boost >= 25 => Confidence::Medium,
                Confidence::Medium if result.confidence_boost >= 25 => Confidence::High,
                Confidence::High if result.confidence_boost >= 50 => Confidence::Confirmed,
                c => c,
            };
            indicator.confidence = new_confidence;
        }
        
        // Boost severity
        if result.severity_boost && indicator.severity < Severity::Critical {
            indicator.severity = match indicator.severity {
                Severity::Info => Severity::Low,
                Severity::Low => Severity::Medium,
                Severity::Medium => Severity::High,
                Severity::High => Severity::Critical,
                Severity::Critical => Severity::Critical,
            };
        }
        
        // Add tags
        for tag in &result.new_tags {
            if !indicator.tags.contains(tag) {
                indicator.tags.push(tag.clone());
            }
        }
        
        // Add related IoCs
        for related in &result.related_indicators {
            if !indicator.related_iocs.contains(related) {
                indicator.related_iocs.push(related.clone());
            }
        }
        
        // Add campaign
        if let Some(campaign) = &result.campaign {
            if indicator.context.campaign.is_none() {
                indicator.context.campaign = Some(campaign.clone());
            }
        }
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

fn default_correlation_rules() -> Vec<CorrelationRule> {
    vec![
        CorrelationRule {
            name: "multi_source_high_confidence".to_string(),
            description: "IoC confirmed by 3+ sources".to_string(),
            conditions: vec![
                CorrelationCondition::MultipleSourcesConfirm { min_sources: 3 },
            ],
            action: CorrelationAction::BoostConfidence(25),
        },
        CorrelationRule {
            name: "apt_campaign_boost".to_string(),
            description: "IoC linked to APT campaign".to_string(),
            conditions: vec![
                CorrelationCondition::KnownCampaign,
            ],
            action: CorrelationAction::BoostSeverity,
        },
    ]
}
