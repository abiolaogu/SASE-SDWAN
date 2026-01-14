//! DLP Module - Integrates with sase-dlp

use super::SecurityModule;
use crate::context::{InspectionContext, ModuleVerdict, VerdictAction, Severity};

/// DLP Module (wraps sase-dlp)
pub struct DlpModule {
    enabled: bool,
    patterns: Vec<DlpPattern>,
}

impl DlpModule {
    pub fn new() -> Self {
        let mut m = Self { enabled: true, patterns: Vec::new() };
        m.load_default_patterns();
        m
    }

    fn load_default_patterns(&mut self) {
        // SSN
        self.patterns.push(DlpPattern {
            name: "ssn",
            regex: r"\b\d{3}-\d{2}-\d{4}\b",
            severity: Severity::High,
        });
        // Credit card
        self.patterns.push(DlpPattern {
            name: "credit_card",
            regex: r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",
            severity: Severity::Critical,
        });
        // API key
        self.patterns.push(DlpPattern {
            name: "api_key",
            regex: r#"\b(?:api[_-]?key|apikey)[:\s]*['"]?([a-zA-Z0-9]{32,})['"]?\b"#,
            severity: Severity::High,
        });
    }

    fn scan_payload(&self, payload: &[u8]) -> Option<(&'static str, Severity)> {
        let text = String::from_utf8_lossy(payload);
        for pattern in &self.patterns {
            if let Ok(re) = regex::Regex::new(pattern.regex) {
                if re.is_match(&text) {
                    return Some((pattern.name, pattern.severity));
                }
            }
        }
        None
    }
}

impl Default for DlpModule {
    fn default() -> Self { Self::new() }
}

impl SecurityModule for DlpModule {
    fn name(&self) -> &'static str { "dlp" }
    fn is_enabled(&self) -> bool { self.enabled }

    fn inspect(&self, ctx: &InspectionContext) -> Option<ModuleVerdict> {
        let payload = ctx.payload.as_bytes();
        if payload.is_empty() { return None; }

        if let Some((pattern_name, severity)) = self.scan_payload(payload) {
            return Some(ModuleVerdict {
                module: self.name(),
                action: VerdictAction::Block,
                reason: format!("Sensitive data detected: {}", pattern_name),
                rule_id: None,
                severity,
            });
        }
        None
    }
}

struct DlpPattern {
    name: &'static str,
    regex: &'static str,
    severity: Severity,
}
