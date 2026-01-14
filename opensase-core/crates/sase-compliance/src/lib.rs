//! OpenSASE Compliance Engine (OCE)
//!
//! Compliance and audit framework for enterprise security standards.
//!
//! # Supported Frameworks
//!
//! - **SOC 2 Type II**: Trust Service Criteria
//! - **ISO 27001:2022**: Information Security Management
//! - **PCI-DSS 4.0**: Payment Card Industry Data Security
//! - **HIPAA**: Health Information Portability and Accountability
//! - **GDPR**: General Data Protection Regulation
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     COMPLIANCE ENGINE (OCE)                             │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │    SOC 2     │  │  ISO 27001   │  │   PCI-DSS    │  │ HIPAA/GDPR  │ │
//! │  │   Type II    │  │    :2022     │  │     4.0      │  │             │ │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
//! │         │                 │                 │                 │        │
//! │  ┌──────▼─────────────────▼─────────────────▼─────────────────▼──────┐ │
//! │  │                  CONTINUOUS MONITORING                            │ │
//! │  │   Automated Checks | Evidence Collection | Compliance Scoring    │ │
//! │  └───────────────────────────────────────────────────────────────────┘ │
//! │                                │                                        │
//! │  ┌──────────────┐  ┌──────────▼─────────┐  ┌──────────────┐           │
//! │  │    Audit     │  │     Evidence       │  │     Risk     │           │
//! │  │    Trail     │  │    Collection      │  │  Assessment  │           │
//! │  │ (Hash Chain) │  │   (Immutable)     │  │  (Register)  │           │
//! │  └──────────────┘  └────────────────────┘  └──────────────┘           │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod frameworks;
pub mod checks;
pub mod evidence;
pub mod audit;
pub mod risk;
pub mod remediation;
pub mod reporting;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;

pub use frameworks::{ComplianceFramework, Control, ControlMapping};
pub use checks::{ComplianceCheck, CheckResult, ComplianceStatus};
pub use evidence::{Evidence, EvidenceStore};
pub use audit::{AuditTrail, AuditEvent};
pub use risk::{Risk, RiskRegister};

/// Compliance error types
#[derive(Debug, Error)]
pub enum ComplianceError {
    #[error("check failed: {0}")]
    CheckFailed(String),
    #[error("evidence error: {0}")]
    Evidence(String),
    #[error("audit error: {0}")]
    Audit(String),
}

/// Main Compliance Engine
pub struct ComplianceEngine {
    /// Framework mappings
    pub frameworks: Arc<RwLock<Vec<ControlMapping>>>,
    /// Automated checks
    pub checks: Arc<checks::CheckEngine>,
    /// Evidence store
    pub evidence: Arc<EvidenceStore>,
    /// Audit trail
    pub audit: Arc<AuditTrail>,
    /// Risk register
    pub risk: Arc<RiskRegister>,
}

impl ComplianceEngine {
    /// Create new compliance engine
    pub fn new() -> Self {
        Self {
            frameworks: Arc::new(RwLock::new(Vec::new())),
            checks: Arc::new(checks::CheckEngine::new()),
            evidence: Arc::new(EvidenceStore::new()),
            audit: Arc::new(AuditTrail::new()),
            risk: Arc::new(RiskRegister::new()),
        }
    }

    /// Load framework mappings
    pub fn load_frameworks(&self) {
        let mut frameworks = self.frameworks.write();
        frameworks.extend(frameworks::soc2::get_mappings());
        frameworks.extend(frameworks::iso27001::get_mappings());
        frameworks.extend(frameworks::pci_dss::get_mappings());
        frameworks.extend(frameworks::hipaa::get_mappings());
        frameworks.extend(frameworks::gdpr::get_mappings());
        tracing::info!("Loaded {} control mappings", frameworks.len());
    }

    /// Run all compliance checks
    pub async fn run_checks(&self) -> Vec<CheckResult> {
        self.checks.run_all().await
    }

    /// Get compliance score for framework
    pub fn get_score(&self, framework: ComplianceFramework) -> ComplianceScore {
        let mappings = self.frameworks.read();
        let framework_controls: Vec<_> = mappings.iter()
            .filter(|m| m.framework == framework)
            .collect();

        let total = framework_controls.len();
        let passing = framework_controls.iter()
            .filter(|m| m.status == ComplianceStatus::Compliant)
            .count();

        ComplianceScore {
            framework,
            total_controls: total,
            passing_controls: passing,
            failing_controls: total - passing,
            score_percent: if total > 0 { (passing as f64 / total as f64) * 100.0 } else { 0.0 },
        }
    }

    /// Generate audit report
    pub fn generate_report(&self, framework: ComplianceFramework) -> ComplianceReport {
        let score = self.get_score(framework);
        let mappings = self.frameworks.read();
        let controls: Vec<_> = mappings.iter()
            .filter(|m| m.framework == framework)
            .cloned()
            .collect();

        ComplianceReport {
            framework,
            generated_at: chrono::Utc::now(),
            score,
            controls,
            evidence_count: self.evidence.count(),
        }
    }
}

impl Default for ComplianceEngine {
    fn default() -> Self { Self::new() }
}

/// Compliance score
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceScore {
    pub framework: ComplianceFramework,
    pub total_controls: usize,
    pub passing_controls: usize,
    pub failing_controls: usize,
    pub score_percent: f64,
}

/// Compliance report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub score: ComplianceScore,
    pub controls: Vec<ControlMapping>,
    pub evidence_count: usize,
}
