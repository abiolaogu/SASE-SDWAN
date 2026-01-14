//! DNS Sinkhole Integration
//!
//! Block malicious domains at DNS level.

use crate::{Indicator, IocType};
use std::collections::HashSet;

/// DNS Sinkhole for blocking malicious domains
pub struct DnsSinkhole {
    /// Sinkhole server endpoint
    endpoint: Option<String>,
    /// Local blocklist for fast lookup
    blocklist: dashmap::DashMap<String, SinkholeEntry>,
    /// Whitelisted domains (never block)
    whitelist: HashSet<String>,
    /// Sinkhole IP (where blocked queries resolve to)
    sinkhole_ip: String,
    /// HTTP client
    client: reqwest::Client,
    /// Statistics
    stats: SinkholeStats,
}

#[derive(Debug, Clone)]
pub struct SinkholeEntry {
    pub domain: String,
    pub reason: String,
    pub category: SinkholeCategory,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub hit_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkholeCategory {
    Malware,
    Phishing,
    C2,
    Spam,
    Adware,
    Tracker,
    Custom,
}

#[derive(Debug, Default)]
pub struct SinkholeStats {
    pub domains_blocked: std::sync::atomic::AtomicU64,
    pub queries_blocked: std::sync::atomic::AtomicU64,
    pub whitelist_hits: std::sync::atomic::AtomicU64,
}

impl DnsSinkhole {
    pub fn new() -> Self {
        Self {
            endpoint: None,
            blocklist: dashmap::DashMap::new(),
            whitelist: default_whitelist(),
            sinkhole_ip: "0.0.0.0".to_string(),
            client: reqwest::Client::new(),
            stats: SinkholeStats::default(),
        }
    }
    
    /// Configure sinkhole server endpoint
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = Some(endpoint.to_string());
        self
    }
    
    /// Set sinkhole IP
    pub fn with_sinkhole_ip(mut self, ip: &str) -> Self {
        self.sinkhole_ip = ip.to_string();
        self
    }
    
    /// Check if domain should be blocked
    pub fn should_block(&self, domain: &str) -> Option<SinkholeEntry> {
        use std::sync::atomic::Ordering;
        
        let normalized = normalize_domain(domain);
        
        // Check whitelist first
        if self.is_whitelisted(&normalized) {
            self.stats.whitelist_hits.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        
        // Check exact match
        if let Some(mut entry) = self.blocklist.get_mut(&normalized) {
            entry.hit_count += 1;
            self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
            return Some(entry.clone());
        }
        
        // Check parent domains
        let parts: Vec<&str> = normalized.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if let Some(mut entry) = self.blocklist.get_mut(&parent) {
                entry.hit_count += 1;
                self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                return Some(entry.clone());
            }
        }
        
        None
    }
    
    /// Add domain to blocklist
    pub fn block(&self, domain: &str, reason: &str, category: SinkholeCategory) {
        use std::sync::atomic::Ordering;
        
        let normalized = normalize_domain(domain);
        
        let entry = SinkholeEntry {
            domain: normalized.clone(),
            reason: reason.to_string(),
            category,
            added_at: chrono::Utc::now(),
            expires_at: None,
            hit_count: 0,
        };
        
        self.blocklist.insert(normalized, entry);
        self.stats.domains_blocked.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Remove domain from blocklist
    pub fn unblock(&self, domain: &str) {
        let normalized = normalize_domain(domain);
        self.blocklist.remove(&normalized);
    }
    
    /// Add domain to whitelist
    pub fn whitelist(&mut self, domain: &str) {
        self.whitelist.insert(normalize_domain(domain));
    }
    
    /// Add indicator to sinkhole if it's a domain
    pub fn add_indicator(&self, indicator: &Indicator) {
        if indicator.ioc_type != IocType::Domain {
            return;
        }
        
        let category = match indicator.context.threat_type {
            Some(crate::ThreatType::Malware) => SinkholeCategory::Malware,
            Some(crate::ThreatType::Phishing) => SinkholeCategory::Phishing,
            Some(crate::ThreatType::C2) => SinkholeCategory::C2,
            Some(crate::ThreatType::Spam) => SinkholeCategory::Spam,
            _ => SinkholeCategory::Custom,
        };
        
        let reason = indicator.context.description
            .clone()
            .unwrap_or_else(|| format!("Blocked by threat intel ({})", indicator.id));
        
        self.block(&indicator.value, &reason, category);
    }
    
    /// Push blocklist to DNS server
    pub async fn sync_to_server(&self) -> Result<SyncResult, SinkholeError> {
        let endpoint = self.endpoint.as_ref()
            .ok_or(SinkholeError::NotConfigured)?;
        
        let domains: Vec<_> = self.blocklist.iter()
            .map(|e| SinkholeUpdate {
                domain: e.domain.clone(),
                action: "block".to_string(),
                category: format!("{:?}", e.category),
                sinkhole_ip: self.sinkhole_ip.clone(),
            })
            .collect();
        
        let response = self.client.post(format!("{}/blocklist/sync", endpoint))
            .json(&domains)
            .send()
            .await
            .map_err(|e| SinkholeError::Network(e.to_string()))?;
        
        if response.status().is_success() {
            Ok(SyncResult {
                domains_synced: domains.len(),
                success: true,
            })
        } else {
            Err(SinkholeError::SyncFailed(response.status().as_u16()))
        }
    }
    
    /// Generate RPZ (Response Policy Zone) format
    pub fn to_rpz(&self) -> String {
        let mut rpz = String::new();
        
        rpz.push_str("; OpenSASE DNS Sinkhole RPZ\n");
        rpz.push_str("; Generated at: ");
        rpz.push_str(&chrono::Utc::now().to_rfc3339());
        rpz.push_str("\n\n");
        
        rpz.push_str("$TTL 300\n");
        rpz.push_str("@ IN SOA localhost. root.localhost. (\n");
        rpz.push_str("    1 ; serial\n");
        rpz.push_str("    3600 ; refresh\n");
        rpz.push_str("    600 ; retry\n");
        rpz.push_str("    86400 ; expire\n");
        rpz.push_str("    300 ; minimum\n");
        rpz.push_str(")\n");
        rpz.push_str("@ IN NS localhost.\n\n");
        
        for entry in self.blocklist.iter() {
            // Block the domain and all subdomains
            rpz.push_str(&format!(
                "{} CNAME . ; {}\n",
                entry.domain,
                entry.reason.replace('\n', " ")
            ));
            rpz.push_str(&format!(
                "*.{} CNAME . ; subdomain\n",
                entry.domain
            ));
        }
        
        rpz
    }
    
    /// Generate Pi-hole format
    pub fn to_pihole(&self) -> String {
        let mut output = String::new();
        
        for entry in self.blocklist.iter() {
            output.push_str(&format!("0.0.0.0 {}\n", entry.domain));
        }
        
        output
    }
    
    /// Generate hosts file format
    pub fn to_hosts(&self) -> String {
        let mut output = String::new();
        
        output.push_str("# OpenSASE DNS Sinkhole\n");
        output.push_str(&format!("# Generated: {}\n\n", chrono::Utc::now().to_rfc3339()));
        
        for entry in self.blocklist.iter() {
            output.push_str(&format!("{} {}\n", self.sinkhole_ip, entry.domain));
        }
        
        output
    }
    
    fn is_whitelisted(&self, domain: &str) -> bool {
        if self.whitelist.contains(domain) {
            return true;
        }
        
        // Check parent domains
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if self.whitelist.contains(&parent) {
                return true;
            }
        }
        
        false
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> SinkholeSnapshot {
        use std::sync::atomic::Ordering;
        
        SinkholeSnapshot {
            domains_blocked: self.stats.domains_blocked.load(Ordering::Relaxed),
            queries_blocked: self.stats.queries_blocked.load(Ordering::Relaxed),
            whitelist_hits: self.stats.whitelist_hits.load(Ordering::Relaxed),
            blocklist_size: self.blocklist.len(),
        }
    }
    
    /// Get top blocked domains
    pub fn top_blocked(&self, limit: usize) -> Vec<(String, u64)> {
        let mut entries: Vec<_> = self.blocklist.iter()
            .map(|e| (e.domain.clone(), e.hit_count))
            .collect();
        
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(limit);
        entries
    }
}

impl Default for DnsSinkhole {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct SinkholeUpdate {
    domain: String,
    action: String,
    category: String,
    sinkhole_ip: String,
}

#[derive(Debug, Clone)]
pub struct SyncResult {
    pub domains_synced: usize,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct SinkholeSnapshot {
    pub domains_blocked: u64,
    pub queries_blocked: u64,
    pub whitelist_hits: u64,
    pub blocklist_size: usize,
}

#[derive(Debug)]
pub enum SinkholeError {
    NotConfigured,
    Network(String),
    SyncFailed(u16),
}

impl std::fmt::Display for SinkholeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "Sinkhole not configured"),
            Self::Network(e) => write!(f, "Network error: {}", e),
            Self::SyncFailed(code) => write!(f, "Sync failed with status: {}", code),
        }
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase()
        .trim_start_matches("www.")
        .trim_end_matches('.')
        .to_string()
}

fn default_whitelist() -> HashSet<String> {
    let mut whitelist = HashSet::new();
    
    // Critical infrastructure
    let domains = [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "apple.com",
        "icloud.com",
        "cloudflare.com",
        "amazonaws.com",
        "azure.com",
        "github.com",
        "githubusercontent.com",
    ];
    
    for domain in domains {
        whitelist.insert(domain.to_string());
    }
    
    whitelist
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sinkhole_blocking() {
        let sinkhole = DnsSinkhole::new();
        
        sinkhole.block("malware.com", "Known malware", SinkholeCategory::Malware);
        
        assert!(sinkhole.should_block("malware.com").is_some());
        assert!(sinkhole.should_block("sub.malware.com").is_some());
        assert!(sinkhole.should_block("safe.com").is_none());
    }
    
    #[test]
    fn test_whitelist() {
        let sinkhole = DnsSinkhole::new();
        
        // Google is whitelisted by default
        assert!(sinkhole.should_block("google.com").is_none());
        assert!(sinkhole.should_block("mail.google.com").is_none());
    }
}
