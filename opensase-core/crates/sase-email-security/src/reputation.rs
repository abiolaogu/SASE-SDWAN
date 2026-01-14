//! Sender Reputation Service
//!
//! IP reputation, domain reputation, and sender history tracking.

use crate::EmailEnvelope;
use std::collections::HashMap;
use std::net::IpAddr;

/// Sender reputation service
pub struct ReputationService {
    /// IP reputation cache
    ip_cache: dashmap::DashMap<IpAddr, IpReputation>,
    /// Domain reputation cache
    domain_cache: dashmap::DashMap<String, DomainReputation>,
    /// Blocked IPs
    blocked_ips: dashmap::DashMap<IpAddr, BlockReason>,
    /// Blocked domains
    blocked_domains: dashmap::DashMap<String, BlockReason>,
}

#[derive(Debug, Clone)]
pub struct ReputationResult {
    pub ip_score: f64,
    pub domain_score: f64,
    pub overall_score: f64,
    pub is_blocked: bool,
    pub block_reason: Option<BlockReason>,
    pub details: ReputationDetails,
}

#[derive(Debug, Clone, Default)]
pub struct ReputationDetails {
    pub ip_first_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub ip_message_count: u64,
    pub ip_spam_count: u64,
    pub ip_country: Option<String>,
    pub ip_asn: Option<u32>,
    pub domain_age_days: Option<u32>,
    pub domain_dmarc_policy: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IpReputation {
    pub ip: IpAddr,
    pub score: f64,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub message_count: u64,
    pub spam_count: u64,
    pub clean_count: u64,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub is_dynamic: bool,
}

#[derive(Debug, Clone)]
pub struct DomainReputation {
    pub domain: String,
    pub score: f64,
    pub age_days: Option<u32>,
    pub has_spf: bool,
    pub has_dkim: bool,
    pub has_dmarc: bool,
    pub dmarc_policy: Option<String>,
    pub message_count: u64,
    pub spam_count: u64,
}

#[derive(Debug, Clone)]
pub enum BlockReason {
    SpamSource,
    Phishing,
    Malware,
    Botnet,
    Blacklisted,
    ManualBlock,
}

impl ReputationService {
    pub fn new() -> Self {
        Self {
            ip_cache: dashmap::DashMap::new(),
            domain_cache: dashmap::DashMap::new(),
            blocked_ips: dashmap::DashMap::new(),
            blocked_domains: dashmap::DashMap::new(),
        }
    }
    
    /// Check sender reputation
    pub async fn check(&self, envelope: &EmailEnvelope) -> ReputationResult {
        let ip = envelope.client_ip;
        let domain = extract_domain(&envelope.mail_from);
        
        // Check blocklists first
        if let Some(reason) = self.blocked_ips.get(&ip) {
            return ReputationResult {
                ip_score: 0.0,
                domain_score: 0.0,
                overall_score: 0.0,
                is_blocked: true,
                block_reason: Some(reason.clone()),
                details: ReputationDetails::default(),
            };
        }
        
        if let Some(reason) = self.blocked_domains.get(&domain) {
            return ReputationResult {
                ip_score: 0.0,
                domain_score: 0.0,
                overall_score: 0.0,
                is_blocked: true,
                block_reason: Some(reason.clone()),
                details: ReputationDetails::default(),
            };
        }
        
        // Get IP reputation
        let ip_rep = self.get_ip_reputation(ip).await;
        let ip_score = ip_rep.as_ref().map(|r| r.score).unwrap_or(50.0);
        
        // Get domain reputation
        let domain_rep = self.get_domain_reputation(&domain).await;
        let domain_score = domain_rep.as_ref().map(|r| r.score).unwrap_or(50.0);
        
        // Calculate overall score
        let overall_score = (ip_score * 0.6 + domain_score * 0.4).max(0.0).min(100.0);
        
        ReputationResult {
            ip_score,
            domain_score,
            overall_score,
            is_blocked: false,
            block_reason: None,
            details: ReputationDetails {
                ip_first_seen: ip_rep.as_ref().map(|r| r.first_seen),
                ip_message_count: ip_rep.as_ref().map(|r| r.message_count).unwrap_or(0),
                ip_spam_count: ip_rep.as_ref().map(|r| r.spam_count).unwrap_or(0),
                ip_country: ip_rep.as_ref().and_then(|r| r.country.clone()),
                ip_asn: ip_rep.as_ref().and_then(|r| r.asn),
                domain_age_days: domain_rep.as_ref().and_then(|r| r.age_days),
                domain_dmarc_policy: domain_rep.as_ref().and_then(|r| r.dmarc_policy.clone()),
            },
        }
    }
    
    async fn get_ip_reputation(&self, ip: IpAddr) -> Option<IpReputation> {
        // Check cache first
        if let Some(rep) = self.ip_cache.get(&ip) {
            return Some(rep.clone());
        }
        
        // In production: query external reputation services
        // For now, create default reputation
        let rep = IpReputation {
            ip,
            score: 50.0,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            message_count: 0,
            spam_count: 0,
            clean_count: 0,
            country: None,
            asn: None,
            is_dynamic: false,
        };
        
        self.ip_cache.insert(ip, rep.clone());
        Some(rep)
    }
    
    async fn get_domain_reputation(&self, domain: &str) -> Option<DomainReputation> {
        if domain.is_empty() {
            return None;
        }
        
        // Check cache
        if let Some(rep) = self.domain_cache.get(domain) {
            return Some(rep.clone());
        }
        
        // Create default reputation
        let rep = DomainReputation {
            domain: domain.to_string(),
            score: 50.0,
            age_days: None,
            has_spf: false,
            has_dkim: false,
            has_dmarc: false,
            dmarc_policy: None,
            message_count: 0,
            spam_count: 0,
        };
        
        self.domain_cache.insert(domain.to_string(), rep.clone());
        Some(rep)
    }
    
    /// Update IP reputation after verdict
    pub fn update_ip_reputation(&self, ip: IpAddr, is_spam: bool) {
        let mut entry = self.ip_cache.entry(ip).or_insert_with(|| IpReputation {
            ip,
            score: 50.0,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            message_count: 0,
            spam_count: 0,
            clean_count: 0,
            country: None,
            asn: None,
            is_dynamic: false,
        });
        
        entry.last_seen = chrono::Utc::now();
        entry.message_count += 1;
        
        if is_spam {
            entry.spam_count += 1;
            entry.score = (entry.score - 5.0).max(0.0);
        } else {
            entry.clean_count += 1;
            entry.score = (entry.score + 1.0).min(100.0);
        }
    }
    
    /// Block an IP
    pub fn block_ip(&self, ip: IpAddr, reason: BlockReason) {
        self.blocked_ips.insert(ip, reason);
    }
    
    /// Block a domain
    pub fn block_domain(&self, domain: &str, reason: BlockReason) {
        self.blocked_domains.insert(domain.to_string(), reason);
    }
    
    /// Unblock an IP
    pub fn unblock_ip(&self, ip: IpAddr) {
        self.blocked_ips.remove(&ip);
    }
}

impl Default for ReputationService {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationResult {
    pub fn is_blocked(&self) -> bool {
        self.is_blocked
    }
}

fn extract_domain(email: &str) -> String {
    email.split('@')
        .nth(1)
        .unwrap_or("")
        .split('>')
        .next()
        .unwrap_or("")
        .to_lowercase()
}
