//! USIE Engine - Orchestrates all inspection modules

use crate::context::{InspectionContext, VerdictSet, ModuleVerdict};
use crate::verdict::{VerdictAggregator, AggregatedVerdict};
use crate::modules::{SecurityModule, firewall, ips, url_filter, dns_security, dlp, antimalware};
use std::sync::Arc;

/// Unified Security Inspection Engine
pub struct UsieEngine {
    modules: Vec<Box<dyn SecurityModule>>,
    aggregator: VerdictAggregator,
    dry_run: bool,
}

impl UsieEngine {
    /// Create new engine with default modules
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            aggregator: VerdictAggregator::new(),
            dry_run: false,
        }
    }

    /// Create engine with all modules enabled
    pub fn with_all_modules() -> Self {
        let mut engine = Self::new();
        engine.add_module(Box::new(firewall::FirewallModule::new()));
        engine.add_module(Box::new(ips::IpsModule::new()));
        engine.add_module(Box::new(url_filter::UrlFilterModule::new()));
        engine.add_module(Box::new(dns_security::DnsSecurityModule::new()));
        engine.add_module(Box::new(dlp::DlpModule::new()));
        engine.add_module(Box::new(antimalware::AntimalwareModule::new()));
        engine
    }

    /// Add inspection module
    pub fn add_module(&mut self, module: Box<dyn SecurityModule>) {
        self.modules.push(module);
    }

    /// Enable dry-run mode
    pub fn set_dry_run(&mut self, enabled: bool) {
        self.dry_run = enabled;
        self.aggregator = VerdictAggregator::new().dry_run(enabled);
    }

    /// Inspect packet (single pass)
    pub fn inspect(&self, ctx: &mut InspectionContext) -> AggregatedVerdict {
        // Run all enabled modules
        for module in &self.modules {
            if module.is_enabled() {
                if let Some(verdict) = module.inspect(ctx) {
                    let action = verdict.action;
                    self.set_verdict(ctx, module.name(), verdict);
                    
                    // Early exit on block (lazy evaluation)
                    if action == crate::context::VerdictAction::Block && !self.dry_run {
                        break;
                    }
                }
            }
        }

        self.aggregator.aggregate(&ctx.verdicts)
    }

    /// Inspect raw packet
    pub fn inspect_packet(&self, packet: &[u8]) -> Option<AggregatedVerdict> {
        let mut ctx = InspectionContext::parse(packet)?;
        Some(self.inspect(&mut ctx))
    }

    fn set_verdict(&self, ctx: &mut InspectionContext, module: &str, verdict: ModuleVerdict) {
        match module {
            "firewall" => ctx.verdicts.firewall = Some(verdict),
            "ips" => ctx.verdicts.ips = Some(verdict),
            "url_filter" => ctx.verdicts.url_filter = Some(verdict),
            "dns_security" => ctx.verdicts.dns_security = Some(verdict),
            "dlp" => ctx.verdicts.dlp = Some(verdict),
            "antimalware" => ctx.verdicts.antimalware = Some(verdict),
            _ => {}
        }
    }

    /// Get module count
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }
}

impl Default for UsieEngine {
    fn default() -> Self {
        Self::with_all_modules()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 54];
        pkt[12] = 0x08; pkt[13] = 0x00;
        pkt[14] = 0x45;
        pkt[23] = 6;
        pkt[26..30].copy_from_slice(&[192, 168, 1, 1]);
        pkt[30..34].copy_from_slice(&[10, 0, 0, 1]);
        pkt[34] = 0x30; pkt[35] = 0x39;
        pkt[36] = 0x01; pkt[37] = 0xBB;
        pkt[46] = 0x50;
        pkt
    }

    #[test]
    fn test_engine_creation() {
        let engine = UsieEngine::with_all_modules();
        assert_eq!(engine.module_count(), 6);
    }

    #[test]
    fn test_packet_inspection() {
        let engine = UsieEngine::with_all_modules();
        let pkt = make_test_packet();
        
        let result = engine.inspect_packet(&pkt);
        assert!(result.is_some());
    }
}
