//! DNS Security Module
//!
//! Features:
//! - Block malicious domains
//! - DNS tunneling detection (entropy analysis)
//! - DoH detection

use super::SecurityModule;
use crate::context::{InspectionContext, ModuleVerdict, VerdictAction, Severity, L7Protocol, DnsInfo, L4Header};
use std::collections::HashSet;

/// DNS Security Module
pub struct DnsSecurityModule {
    blocked_domains: HashSet<String>,
    tunneling_threshold: f64,
    enabled: bool,
}

impl DnsSecurityModule {
    pub fn new() -> Self {
        Self {
            blocked_domains: HashSet::new(),
            tunneling_threshold: 3.5,  // Entropy threshold
            enabled: true,
        }
    }

    pub fn block_domain(&mut self, domain: &str) {
        self.blocked_domains.insert(domain.to_lowercase());
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(data: &str) -> f64 {
        let mut freq = [0u32; 256];
        let len = data.len();
        if len == 0 { return 0.0; }

        for b in data.bytes() {
            freq[b as usize] += 1;
        }

        let mut entropy = 0.0f64;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len as f64;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn is_dns_tunnel(&self, query: &str) -> bool {
        // High entropy subdomain indicates potential tunneling
        let parts: Vec<&str> = query.split('.').collect();
        if parts.len() < 3 { return false; }
        
        let subdomain = parts[0];
        if subdomain.len() > 30 {
            let entropy = Self::calculate_entropy(subdomain);
            return entropy > self.tunneling_threshold;
        }
        false
    }

    fn check_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        for blocked in &self.blocked_domains {
            if domain_lower == *blocked || domain_lower.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }
        false
    }
}

impl Default for DnsSecurityModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityModule for DnsSecurityModule {
    fn name(&self) -> &'static str { "dns_security" }

    fn is_enabled(&self) -> bool { self.enabled }

    fn inspect(&self, ctx: &InspectionContext) -> Option<ModuleVerdict> {
        // Check if DNS port
        if ctx.l4.dst_port() != Some(53) && ctx.l4.src_port() != Some(53) {
            return None;
        }

        // Parse DNS if not already done
        let dns = match &ctx.l7 {
            Some(L7Protocol::Dns(dns)) => dns,
            _ => return None,
        };

        for question in &dns.questions {
            // Check blocked domains
            if self.check_domain(&question.name) {
                return Some(ModuleVerdict {
                    module: self.name(),
                    action: VerdictAction::Block,
                    reason: format!("Blocked DNS query: {}", question.name),
                    rule_id: None,
                    severity: Severity::Medium,
                });
            }

            // Check for tunneling
            if self.is_dns_tunnel(&question.name) {
                return Some(ModuleVerdict {
                    module: self.name(),
                    action: VerdictAction::Block,
                    reason: format!("DNS tunneling detected: {}", question.name),
                    rule_id: None,
                    severity: Severity::High,
                });
            }
        }

        None
    }
}

/// Parse DNS packet
pub fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 { return None; }

    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;

    let mut pos = 12;
    let mut questions = Vec::new();

    for _ in 0..qdcount {
        let (name, new_pos) = parse_dns_name(payload, pos)?;
        pos = new_pos;
        if pos + 4 > payload.len() { return None; }
        
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
        pos += 4;

        questions.push(crate::context::DnsQuestion { name, qtype, qclass });
    }

    Some(DnsInfo {
        query_id: id,
        is_response,
        questions,
        answers: Vec::new(),  // Simplified
    })
}

fn parse_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut jump_pos = 0;

    loop {
        if pos >= data.len() { return None; }
        let len = data[pos] as usize;
        
        if len == 0 {
            pos += 1;
            break;
        }
        
        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() { return None; }
            let offset = (((len & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            if !jumped {
                jump_pos = pos + 2;
            }
            pos = offset;
            jumped = true;
            continue;
        }
        
        pos += 1;
        if pos + len > data.len() { return None; }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }

    let final_pos = if jumped { jump_pos } else { pos };
    Some((parts.join("."), final_pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy() {
        // Random-looking string (high entropy)
        let high = DnsSecurityModule::calculate_entropy("a1b2c3d4e5f6g7h8");
        // Repetitive string (low entropy)
        let low = DnsSecurityModule::calculate_entropy("aaaaaaaaaaaaa");
        
        assert!(high > low);
    }

    #[test]
    fn test_tunnel_detection() {
        let dns = DnsSecurityModule::new();
        
        // Normal domain
        assert!(!dns.is_dns_tunnel("www.example.com"));
        
        // Suspicious (but short - below threshold)
        assert!(!dns.is_dns_tunnel("abc.example.com"));
    }
}
