//! Compliance Reporting

use crate::{ComplianceScore, ComplianceEngine};
use crate::frameworks::ComplianceFramework;
use serde::{Deserialize, Serialize};

/// Report generator
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate executive summary
    pub fn executive_summary(engine: &ComplianceEngine) -> ExecutiveSummary {
        let frameworks = [
            ComplianceFramework::Soc2TypeII,
            ComplianceFramework::Iso27001_2022,
            ComplianceFramework::PciDss4_0,
            ComplianceFramework::Hipaa,
            ComplianceFramework::Gdpr,
        ];

        let scores: Vec<_> = frameworks.iter()
            .map(|f| engine.get_score(*f))
            .collect();

        let overall = scores.iter()
            .map(|s| s.score_percent)
            .sum::<f64>() / scores.len() as f64;

        ExecutiveSummary {
            overall_score: overall,
            framework_scores: scores,
            risk_summary: engine.risk.summary(),
            generated_at: chrono::Utc::now(),
        }
    }

    /// Generate gap analysis
    pub fn gap_analysis(engine: &ComplianceEngine, framework: ComplianceFramework) -> GapAnalysis {
        let mappings = engine.frameworks.read();
        let gaps: Vec<_> = mappings.iter()
            .filter(|m| m.framework == framework)
            .filter(|m| m.status != crate::checks::ComplianceStatus::Compliant)
            .map(|m| Gap {
                control_id: m.control.id.clone(),
                control_name: m.control.name.clone(),
                status: m.status,
                remediation_priority: determine_priority(&m.control.category),
            })
            .collect();

        GapAnalysis {
            framework,
            total_controls: mappings.iter().filter(|m| m.framework == framework).count(),
            gaps: gaps.clone(),
            gap_count: gaps.len(),
            generated_at: chrono::Utc::now(),
        }
    }

    /// Generate auditor package
    pub fn auditor_package(engine: &ComplianceEngine, framework: ComplianceFramework) -> AuditorPackage {
        let report = engine.generate_report(framework);
        let evidence = engine.evidence.export(&framework.to_string());
        
        AuditorPackage {
            framework,
            report,
            evidence_package_id: evidence.id,
            evidence_count: evidence.evidence.len(),
            generated_at: chrono::Utc::now(),
        }
    }
}

fn determine_priority(category: &str) -> Priority {
    match category {
        "Access Control" | "Technical Safeguards" => Priority::High,
        "Encryption" | "Logging" => Priority::High,
        _ => Priority::Medium,
    }
}

/// Executive summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub overall_score: f64,
    pub framework_scores: Vec<ComplianceScore>,
    pub risk_summary: crate::risk::RiskSummary,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Gap analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapAnalysis {
    pub framework: ComplianceFramework,
    pub total_controls: usize,
    pub gaps: Vec<Gap>,
    pub gap_count: usize,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    pub control_id: String,
    pub control_name: String,
    pub status: crate::checks::ComplianceStatus,
    pub remediation_priority: Priority,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

/// Auditor package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditorPackage {
    pub framework: ComplianceFramework,
    pub report: crate::ComplianceReport,
    pub evidence_package_id: String,
    pub evidence_count: usize,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}
