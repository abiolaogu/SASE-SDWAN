//! URL/Domain Filtering Module
//!
//! Features:
//! - Bloom filter for known-bad domains
//! - Category lookup
//! - SNI extraction from TLS ClientHello

use super::SecurityModule;
use crate::context::{InspectionContext, ModuleVerdict, VerdictAction, Severity, L7Protocol, TlsInfo, HttpInfo};
use std::collections::HashSet;

/// URL Filter Module
pub struct UrlFilterModule {
    blocked_domains: HashSet<String>,
    blocked_categories: HashSet<String>,
    category_db: Vec<(String, String)>,  // domain -> category
    enabled: bool,
}

impl UrlFilterModule {
    pub fn new() -> Self {
        Self {
            blocked_domains: HashSet::new(),
            blocked_categories: HashSet::new(),
            category_db: Vec::new(),
            enabled: true,
        }
    }

    pub fn block_domain(&mut self, domain: &str) {
        self.blocked_domains.insert(domain.to_lowercase());
    }

    pub fn block_category(&mut self, category: &str) {
        self.blocked_categories.insert(category.to_lowercase());
    }

    pub fn add_category_entry(&mut self, domain: &str, category: &str) {
        self.category_db.push((domain.to_lowercase(), category.to_lowercase()));
    }

    /// Load blocklist (one domain per line)
    pub fn load_blocklist(&mut self, list: &str) {
        for line in list.lines() {
            let domain = line.trim();
            if !domain.is_empty() && !domain.starts_with('#') {
                self.block_domain(domain);
            }
        }
    }

    fn extract_domain(&self, ctx: &InspectionContext) -> Option<String> {
        match &ctx.l7 {
            Some(L7Protocol::Https(tls)) => tls.sni.clone(),
            Some(L7Protocol::Http(http)) => http.host.clone(),
            _ => None,
        }
    }

    fn get_category(&self, domain: &str) -> Option<&str> {
        let domain_lower = domain.to_lowercase();
        for (d, cat) in &self.category_db {
            if domain_lower.ends_with(d) || domain_lower == *d {
                return Some(cat);
            }
        }
        None
    }

    fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // Direct match
        if self.blocked_domains.contains(&domain_lower) {
            return true;
        }

        // Subdomain match
        for blocked in &self.blocked_domains {
            if domain_lower.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }

        // Category match
        if let Some(cat) = self.get_category(&domain_lower) {
            if self.blocked_categories.contains(cat) {
                return true;
            }
        }

        false
    }
}

impl Default for UrlFilterModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityModule for UrlFilterModule {
    fn name(&self) -> &'static str { "url_filter" }

    fn is_enabled(&self) -> bool { self.enabled }

    fn inspect(&self, ctx: &InspectionContext) -> Option<ModuleVerdict> {
        let domain = self.extract_domain(ctx)?;
        
        if self.is_blocked(&domain) {
            return Some(ModuleVerdict {
                module: self.name(),
                action: VerdictAction::Block,
                reason: format!("Blocked domain: {}", domain),
                rule_id: None,
                severity: Severity::Medium,
            });
        }

        None
    }
}

/// Extract SNI from TLS ClientHello
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    if payload.len() < 43 { return None; }
    if payload[0] != 0x16 { return None; }  // Not handshake
    
    // Skip to handshake
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len { return None; }
    
    let hs = &payload[5..];
    if hs.is_empty() || hs[0] != 0x01 { return None; }  // Not ClientHello
    
    // Skip: type(1) + length(3) + version(2) + random(32)
    let mut pos = 38;
    if hs.len() < pos + 1 { return None; }
    
    // Session ID length
    let session_len = hs[pos] as usize;
    pos += 1 + session_len;
    if hs.len() < pos + 2 { return None; }
    
    // Cipher suites length
    let cipher_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if hs.len() < pos + 1 { return None; }
    
    // Compression length
    let comp_len = hs[pos] as usize;
    pos += 1 + comp_len;
    if hs.len() < pos + 2 { return None; }
    
    // Extensions length
    let ext_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    
    // Parse extensions
    while pos + 4 <= ext_end && pos + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        
        if ext_type == 0 {  // SNI extension
            if pos + 5 <= hs.len() && ext_data_len >= 5 {
                let sni_len = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                if pos + 5 + sni_len <= hs.len() {
                    let sni = &hs[pos + 5..pos + 5 + sni_len];
                    return String::from_utf8(sni.to_vec()).ok();
                }
            }
        }
        pos += ext_data_len;
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_blocking() {
        let mut filter = UrlFilterModule::new();
        filter.block_domain("malware.com");
        filter.block_domain("evil.org");

        assert!(filter.is_blocked("malware.com"));
        assert!(filter.is_blocked("sub.malware.com"));
        assert!(!filter.is_blocked("safe.com"));
    }

    #[test]
    fn test_category_blocking() {
        let mut filter = UrlFilterModule::new();
        filter.add_category_entry("gambling.com", "gambling");
        filter.block_category("gambling");

        assert!(filter.is_blocked("gambling.com"));
    }
}
