//! Compliance Framework Definitions

pub mod soc2;
pub mod iso27001;
pub mod pci_dss;
pub mod hipaa;
pub mod gdpr;

use serde::{Deserialize, Serialize};
use crate::checks::ComplianceStatus;

/// Compliance framework
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    Soc2TypeII,
    Iso27001_2022,
    PciDss4_0,
    Hipaa,
    Gdpr,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Soc2TypeII => write!(f, "SOC 2 Type II"),
            Self::Iso27001_2022 => write!(f, "ISO 27001:2022"),
            Self::PciDss4_0 => write!(f, "PCI-DSS 4.0"),
            Self::Hipaa => write!(f, "HIPAA"),
            Self::Gdpr => write!(f, "GDPR"),
        }
    }
}

/// Control definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub framework: ComplianceFramework,
}

/// Control mapping to platform features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMapping {
    pub control: Control,
    pub framework: ComplianceFramework,
    pub platform_feature: String,
    pub check_id: Option<String>,
    pub status: ComplianceStatus,
    pub evidence_types: Vec<String>,
    pub implementation_notes: String,
}
