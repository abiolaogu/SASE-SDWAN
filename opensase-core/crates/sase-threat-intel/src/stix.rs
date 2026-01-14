//! STIX/TAXII Integration
//!
//! Support for STIX 2.1 format and TAXII 2.1 protocol.

use crate::{Indicator, IocType, FeedConfig, Confidence, Severity, IntelSource, IocContext, ThreatType};
use serde::{Deserialize, Serialize};
use crate::feeds::FeedError;

/// STIX 2.1 Bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
    pub objects: Vec<StixObject>,
}

/// STIX 2.1 Object (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StixObject {
    #[serde(rename = "indicator")]
    Indicator(StixIndicator),
    #[serde(rename = "malware")]
    Malware(StixMalware),
    #[serde(rename = "attack-pattern")]
    AttackPattern(StixAttackPattern),
    #[serde(rename = "threat-actor")]
    ThreatActor(StixThreatActor),
    #[serde(rename = "campaign")]
    Campaign(StixCampaign),
    #[serde(rename = "relationship")]
    Relationship(StixRelationship),
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    pub id: String,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub confidence: Option<u32>,
    pub labels: Option<Vec<String>>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    pub external_references: Option<Vec<ExternalReference>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixMalware {
    pub id: String,
    pub name: String,
    pub malware_types: Option<Vec<String>>,
    pub description: Option<String>,
    pub aliases: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixAttackPattern {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub external_references: Option<Vec<ExternalReference>>,
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixThreatActor {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub sophistication: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixCampaign {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixRelationship {
    pub id: String,
    pub relationship_type: String,
    pub source_ref: String,
    pub target_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source_name: String,
    pub url: Option<String>,
    pub external_id: Option<String>,
}

/// Parse STIX bundle and convert to internal indicators
pub fn parse_stix_bundle(json: &str, config: &FeedConfig) -> Result<Vec<Indicator>, FeedError> {
    let bundle: StixBundle = serde_json::from_str(json)
        .map_err(|e| FeedError::Parse(e.to_string()))?;
    
    let mut indicators = Vec::new();
    let mut malware_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut attack_patterns: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    
    // First pass: collect malware and attack patterns
    for obj in &bundle.objects {
        match obj {
            StixObject::Malware(m) => {
                malware_map.insert(m.id.clone(), m.name.clone());
            }
            StixObject::AttackPattern(ap) => {
                if let Some(refs) = &ap.external_references {
                    for r in refs {
                        if r.source_name == "mitre-attack" {
                            if let Some(ext_id) = &r.external_id {
                                attack_patterns.entry(ap.id.clone())
                                    .or_default()
                                    .push(ext_id.clone());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    
    // Second pass: parse indicators
    for obj in bundle.objects {
        if let StixObject::Indicator(stix_ind) = obj {
            if let Some(indicator) = parse_stix_indicator(&stix_ind, config) {
                indicators.push(indicator);
            }
        }
    }
    
    Ok(indicators)
}

/// Parse individual STIX indicator
fn parse_stix_indicator(stix: &StixIndicator, config: &FeedConfig) -> Option<Indicator> {
    // Parse pattern
    let (ioc_type, value) = parse_pattern(&stix.pattern)?;
    
    // Parse dates
    let first_seen = chrono::DateTime::parse_from_rfc3339(&stix.valid_from)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    
    let expires_at = stix.valid_until.as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    
    // Map confidence
    let confidence = match stix.confidence {
        Some(c) if c >= 90 => Confidence::Confirmed,
        Some(c) if c >= 70 => Confidence::High,
        Some(c) if c >= 40 => Confidence::Medium,
        Some(c) if c >= 20 => Confidence::Low,
        _ => config.default_confidence,
    };
    
    // Extract MITRE info from kill chain phases
    let mut mitre_tactics = Vec::new();
    let mut mitre_techniques = Vec::new();
    
    if let Some(phases) = &stix.kill_chain_phases {
        for phase in phases {
            if phase.kill_chain_name == "mitre-attack" {
                mitre_tactics.push(phase.phase_name.clone());
            }
        }
    }
    
    // Extract MITRE from external references
    if let Some(refs) = &stix.external_references {
        for r in refs {
            if r.source_name == "mitre-attack" {
                if let Some(id) = &r.external_id {
                    mitre_techniques.push(id.clone());
                }
            }
        }
    }
    
    // Determine threat type from labels
    let threat_type = stix.labels.as_ref()
        .and_then(|labels| labels.first())
        .and_then(|l| label_to_threat_type(l));
    
    Some(Indicator {
        id: stix.id.clone(),
        ioc_type,
        value,
        confidence,
        severity: Severity::Medium,
        first_seen,
        last_seen: chrono::Utc::now(),
        expires_at,
        sources: vec![IntelSource {
            name: config.name.clone(),
            feed_id: config.id.clone(),
            reliability: config.reliability,
            timestamp: chrono::Utc::now(),
            reference_url: stix.external_references.as_ref()
                .and_then(|refs| refs.first())
                .and_then(|r| r.url.clone()),
        }],
        tags: stix.labels.clone().unwrap_or_default(),
        context: IocContext {
            threat_type,
            description: stix.description.clone(),
            kill_chain_phases: stix.kill_chain_phases.as_ref()
                .map(|p| p.iter().map(|k| k.phase_name.clone()).collect())
                .unwrap_or_default(),
            ..Default::default()
        },
        mitre_tactics,
        mitre_techniques,
        related_iocs: Vec::new(),
    })
}

/// Parse STIX pattern to extract IoC type and value
fn parse_pattern(pattern: &str) -> Option<(IocType, String)> {
    // Pattern format: [type:property = 'value']
    let re = regex::Regex::new(r"\[([^\]:]+):([^\]]+)\s*=\s*'([^']+)'\]").ok()?;
    
    let caps = re.captures(pattern)?;
    let obj_type = caps.get(1)?.as_str();
    let value = caps.get(3)?.as_str();
    
    let ioc_type = match obj_type {
        "ipv4-addr" => IocType::IPv4,
        "ipv6-addr" => IocType::IPv6,
        "domain-name" => IocType::Domain,
        "url" => IocType::Url,
        "file" => {
            // Check which hash type
            let prop = caps.get(2)?.as_str();
            match prop {
                s if s.contains("MD5") => IocType::FileHashMd5,
                s if s.contains("SHA-1") => IocType::FileHashSha1,
                s if s.contains("SHA-256") => IocType::FileHashSha256,
                _ => IocType::FileHashSha256,
            }
        }
        "email-addr" => IocType::Email,
        "vulnerability" => IocType::Cve,
        "autonomous-system" => IocType::Asn,
        "user-agent" => IocType::UserAgent,
        _ => return None,
    };
    
    Some((ioc_type, value.to_string()))
}

/// Map STIX label to threat type
fn label_to_threat_type(label: &str) -> Option<ThreatType> {
    match label.to_lowercase().as_str() {
        "malware" | "malicious-activity" => Some(ThreatType::Malware),
        "botnet" => Some(ThreatType::Botnet),
        "c2" | "command-and-control" => Some(ThreatType::C2),
        "phishing" => Some(ThreatType::Phishing),
        "spam" => Some(ThreatType::Spam),
        "scanner" | "scanning" => Some(ThreatType::Scanner),
        "exploit" | "exploitation" => Some(ThreatType::Exploit),
        "ransomware" => Some(ThreatType::Ransomware),
        "apt" | "targeted-attack" => Some(ThreatType::Apt),
        "cryptominer" | "cryptomining" => Some(ThreatType::Cryptominer),
        "proxy" | "anonymization" => Some(ThreatType::Proxy),
        "tor" => Some(ThreatType::Tor),
        _ => None,
    }
}

/// TAXII 2.1 Client
pub struct TaxiiClient {
    client: reqwest::Client,
    discovery_url: String,
    api_root: Option<String>,
    api_key: Option<String>,
}

impl TaxiiClient {
    pub fn new(discovery_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            discovery_url: discovery_url.to_string(),
            api_root: None,
            api_key: None,
        }
    }
    
    pub fn with_api_key(mut self, api_key: &str) -> Self {
        self.api_key = Some(api_key.to_string());
        self
    }
    
    /// Discover API roots
    pub async fn discover(&mut self) -> Result<Vec<String>, FeedError> {
        let mut req = self.client.get(&self.discovery_url)
            .header("Accept", "application/taxii+json;version=2.1");
        
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        
        let resp = req.send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body: serde_json::Value = resp.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        let roots = body.get("api_roots")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect())
            .unwrap_or_default();
        
        if let Some(first) = roots.first() {
            self.api_root = Some(first.clone());
        }
        
        Ok(roots)
    }
    
    /// Get collections from API root
    pub async fn get_collections(&self) -> Result<Vec<TaxiiCollection>, FeedError> {
        let api_root = self.api_root.as_ref()
            .ok_or(FeedError::Network("No API root discovered".to_string()))?;
        
        let url = format!("{}/collections/", api_root);
        
        let mut req = self.client.get(&url)
            .header("Accept", "application/taxii+json;version=2.1");
        
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        
        let resp = req.send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let body: serde_json::Value = resp.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        let collections = body.get("collections")
            .and_then(|c| serde_json::from_value::<Vec<TaxiiCollection>>(c.clone()).ok())
            .unwrap_or_default();
        
        Ok(collections)
    }
    
    /// Get objects from a collection
    pub async fn get_objects(&self, collection_id: &str) -> Result<StixBundle, FeedError> {
        let api_root = self.api_root.as_ref()
            .ok_or(FeedError::Network("No API root discovered".to_string()))?;
        
        let url = format!("{}/collections/{}/objects/", api_root, collection_id);
        
        let mut req = self.client.get(&url)
            .header("Accept", "application/taxii+json;version=2.1");
        
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        
        let resp = req.send().await
            .map_err(|e| FeedError::Network(e.to_string()))?;
        
        let bundle: StixBundle = resp.json().await
            .map_err(|e| FeedError::Parse(e.to_string()))?;
        
        Ok(bundle)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiCollection {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Option<Vec<String>>,
}
