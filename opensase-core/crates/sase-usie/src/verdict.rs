//! Verdict types and aggregation

use crate::context::{ModuleVerdict, VerdictAction, VerdictSet, Severity};

/// Final aggregated verdict
#[derive(Debug, Clone)]
pub struct AggregatedVerdict {
    pub action: VerdictAction,
    pub reasons: Vec<String>,
    pub blocking_module: Option<&'static str>,
    pub highest_severity: Severity,
    pub rule_ids: Vec<u32>,
}

/// Verdict aggregator
pub struct VerdictAggregator {
    dry_run: bool,
}

impl VerdictAggregator {
    pub fn new() -> Self {
        Self { dry_run: false }
    }

    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Aggregate all verdicts into final decision
    pub fn aggregate(&self, verdicts: &VerdictSet) -> AggregatedVerdict {
        let mut result = AggregatedVerdict {
            action: VerdictAction::Allow,
            reasons: Vec::new(),
            blocking_module: None,
            highest_severity: Severity::Info,
            rule_ids: Vec::new(),
        };

        // Check all modules
        let all_verdicts = [
            &verdicts.firewall,
            &verdicts.ips,
            &verdicts.url_filter,
            &verdicts.dns_security,
            &verdicts.dlp,
            &verdicts.antimalware,
        ];

        for verdict in all_verdicts.iter().filter_map(|v| v.as_ref()) {
            // Track highest severity
            if verdict.severity > result.highest_severity {
                result.highest_severity = verdict.severity;
            }

            // Collect rule IDs
            if let Some(id) = verdict.rule_id {
                result.rule_ids.push(id);
            }

            // Priority: Block > Redirect > Throttle > Log > Allow
            if verdict.action > result.action {
                result.action = verdict.action;
                result.blocking_module = Some(verdict.module);
            }

            // Collect reasons
            if verdict.action >= VerdictAction::Log {
                result.reasons.push(format!(
                    "[{}] {}",
                    verdict.module, verdict.reason
                ));
            }
        }

        // Dry run mode - log but don't block
        if self.dry_run && result.action == VerdictAction::Block {
            result.action = VerdictAction::Log;
            result.reasons.push("[DRY-RUN] Would have blocked".to_string());
        }

        result
    }
}

impl Default for VerdictAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_priority() {
        let mut verdicts = VerdictSet::default();
        
        verdicts.firewall = Some(ModuleVerdict {
            module: "firewall",
            action: VerdictAction::Allow,
            reason: "Rule 1 matched".into(),
            rule_id: Some(1),
            severity: Severity::Info,
        });
        
        verdicts.ips = Some(ModuleVerdict {
            module: "ips",
            action: VerdictAction::Block,
            reason: "Signature 12345 matched".into(),
            rule_id: Some(12345),
            severity: Severity::High,
        });

        let agg = VerdictAggregator::new();
        let result = agg.aggregate(&verdicts);

        assert_eq!(result.action, VerdictAction::Block);
        assert_eq!(result.blocking_module, Some("ips"));
        assert_eq!(result.highest_severity, Severity::High);
    }

    #[test]
    fn test_dry_run() {
        let mut verdicts = VerdictSet::default();
        verdicts.dlp = Some(ModuleVerdict {
            module: "dlp",
            action: VerdictAction::Block,
            reason: "PII detected".into(),
            rule_id: Some(99),
            severity: Severity::Critical,
        });

        let agg = VerdictAggregator::new().dry_run(true);
        let result = agg.aggregate(&verdicts);

        assert_eq!(result.action, VerdictAction::Log);
        assert!(result.reasons.iter().any(|r| r.contains("DRY-RUN")));
    }
}
