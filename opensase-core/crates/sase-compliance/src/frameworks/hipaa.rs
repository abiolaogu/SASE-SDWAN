//! HIPAA Framework

use super::{Control, ControlMapping, ComplianceFramework};
use crate::checks::ComplianceStatus;

/// Get HIPAA control mappings
pub fn get_mappings() -> Vec<ControlMapping> {
    vec![
        // Technical Safeguards
        ControlMapping {
            control: Control {
                id: "164.312(a)(1)".into(),
                name: "Access Control".into(),
                description: "Implement technical policies to allow access only to authorized persons".into(),
                category: "Technical Safeguards".into(),
                framework: ComplianceFramework::Hipaa,
            },
            framework: ComplianceFramework::Hipaa,
            platform_feature: "RBAC".into(),
            check_id: Some("hipaa-access-control".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["access_policy".into(), "rbac_config".into()],
            implementation_notes: "Role-based access to PHI".into(),
        },
        ControlMapping {
            control: Control {
                id: "164.312(a)(2)(i)".into(),
                name: "Unique User Identification".into(),
                description: "Assign unique name/number for identifying and tracking user identity".into(),
                category: "Technical Safeguards".into(),
                framework: ComplianceFramework::Hipaa,
            },
            framework: ComplianceFramework::Hipaa,
            platform_feature: "Identity".into(),
            check_id: Some("hipaa-unique-id".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["user_directory".into()],
            implementation_notes: "Unique user IDs for all accounts".into(),
        },
        ControlMapping {
            control: Control {
                id: "164.312(a)(2)(iv)".into(),
                name: "Encryption and Decryption".into(),
                description: "Implement mechanism to encrypt and decrypt ePHI".into(),
                category: "Technical Safeguards".into(),
                framework: ComplianceFramework::Hipaa,
            },
            framework: ComplianceFramework::Hipaa,
            platform_feature: "Encryption".into(),
            check_id: Some("check-encryption-at-rest".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["encryption_config".into()],
            implementation_notes: "AES-256 for all ePHI".into(),
        },
        ControlMapping {
            control: Control {
                id: "164.312(b)".into(),
                name: "Audit Controls".into(),
                description: "Implement hardware, software, and procedures to record and examine access".into(),
                category: "Technical Safeguards".into(),
                framework: ComplianceFramework::Hipaa,
            },
            framework: ComplianceFramework::Hipaa,
            platform_feature: "Audit Trail".into(),
            check_id: Some("check-logging".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["audit_logs".into()],
            implementation_notes: "Comprehensive audit logging with hash chain".into(),
        },
        ControlMapping {
            control: Control {
                id: "164.312(c)(1)".into(),
                name: "Integrity".into(),
                description: "Policies to protect ePHI from improper alteration or destruction".into(),
                category: "Technical Safeguards".into(),
                framework: ComplianceFramework::Hipaa,
            },
            framework: ComplianceFramework::Hipaa,
            platform_feature: "Data Integrity".into(),
            check_id: Some("hipaa-integrity".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["integrity_checks".into()],
            implementation_notes: "Checksums and immutable storage".into(),
        },
        ControlMapping {
            control: Control {
                id: "164.312(e)(1)".into(),
                name: "Transmission Security".into(),
                description: "Implement technical security measures to guard against unauthorized access to ePHI during transmission".into(),
                category: "Technical Safeguards".into(),
                framework: ComplianceFramework::Hipaa,
            },
            framework: ComplianceFramework::Hipaa,
            platform_feature: "TLS".into(),
            check_id: Some("check-tls-enabled".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["tls_config".into()],
            implementation_notes: "TLS 1.2+ for all transmissions".into(),
        },
    ]
}
