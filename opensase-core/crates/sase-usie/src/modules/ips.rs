//! Intrusion Prevention System (IPS) Module
//!
//! Pattern matching against signatures (Suricata-compatible).

use super::SecurityModule;
use crate::context::{InspectionContext, ModuleVerdict, VerdictAction, Severity};
use aho_corasick::AhoCorasick;

/// IPS Module
pub struct IpsModule {
    signatures: Vec<IpsSignature>,
    matcher: Option<AhoCorasick>,
    enabled: bool,
}

impl IpsModule {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            matcher: None,
            enabled: true,
        }
    }

    pub fn add_signature(&mut self, sig: IpsSignature) {
        self.signatures.push(sig);
    }

    /// Compile signatures into Aho-Corasick automaton
    pub fn compile(&mut self) {
        let patterns: Vec<&[u8]> = self.signatures
            .iter()
            .map(|s| s.pattern.as_slice())
            .collect();
        
        if !patterns.is_empty() {
            self.matcher = Some(AhoCorasick::new(&patterns).unwrap());
        }
    }

    /// Load Suricata rules (simplified parser)
    pub fn load_suricata_rules(&mut self, rules: &str) {
        for line in rules.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if let Some(sig) = Self::parse_suricata_rule(line) {
                self.add_signature(sig);
            }
        }
        self.compile();
    }

    fn parse_suricata_rule(line: &str) -> Option<IpsSignature> {
        // Simplified: extract content:"..." and sid:N
        let content_start = line.find("content:\"")?;
        let content_end = line[content_start + 9..].find('"')?;
        let pattern = line[content_start + 9..content_start + 9 + content_end].as_bytes().to_vec();

        let sid = line.find("sid:")
            .and_then(|i| {
                let s = &line[i + 4..];
                let end = s.find(';').unwrap_or(s.len());
                s[..end].parse().ok()
            })
            .unwrap_or(0);

        let msg = line.find("msg:\"")
            .map(|i| {
                let s = &line[i + 5..];
                let end = s.find('"').unwrap_or(s.len());
                s[..end].to_string()
            })
            .unwrap_or_default();

        Some(IpsSignature {
            sid,
            pattern,
            message: msg,
            severity: Severity::High,
            action: VerdictAction::Block,
        })
    }
}

impl Default for IpsModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityModule for IpsModule {
    fn name(&self) -> &'static str { "ips" }

    fn is_enabled(&self) -> bool { self.enabled }

    fn inspect(&self, ctx: &InspectionContext) -> Option<ModuleVerdict> {
        let matcher = self.matcher.as_ref()?;
        let payload = ctx.payload.as_bytes();
        
        if payload.is_empty() {
            return None;
        }

        // Find first match
        for mat in matcher.find_iter(payload) {
            let sig = &self.signatures[mat.pattern().as_usize()];
            return Some(ModuleVerdict {
                module: self.name(),
                action: sig.action,
                reason: sig.message.clone(),
                rule_id: Some(sig.sid),
                severity: sig.severity,
            });
        }

        None
    }
}

/// IPS Signature
#[derive(Debug, Clone)]
pub struct IpsSignature {
    pub sid: u32,
    pub pattern: Vec<u8>,
    pub message: String,
    pub severity: Severity,
    pub action: VerdictAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ips_pattern_match() {
        let mut ips = IpsModule::new();
        ips.add_signature(IpsSignature {
            sid: 1001,
            pattern: b"/etc/passwd".to_vec(),
            message: "Path traversal attempt".into(),
            severity: Severity::High,
            action: VerdictAction::Block,
        });
        ips.compile();

        // Would test with payload containing pattern
    }

    #[test]
    fn test_suricata_parse() {
        let rule = r#"alert http any any -> any any (msg:"Test rule"; content:"malware"; sid:12345; rev:1;)"#;
        let sig = IpsModule::parse_suricata_rule(rule).unwrap();
        
        assert_eq!(sig.sid, 12345);
        assert_eq!(sig.pattern, b"malware");
    }
}
