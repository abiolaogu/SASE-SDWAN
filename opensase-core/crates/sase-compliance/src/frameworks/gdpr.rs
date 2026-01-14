//! GDPR Framework

use super::{Control, ControlMapping, ComplianceFramework};
use crate::checks::ComplianceStatus;

/// Get GDPR control mappings
pub fn get_mappings() -> Vec<ControlMapping> {
    vec![
        // Article 32 - Security of Processing
        ControlMapping {
            control: Control {
                id: "Art.32(1)(a)".into(),
                name: "Pseudonymisation and Encryption".into(),
                description: "The pseudonymisation and encryption of personal data".into(),
                category: "Security of Processing".into(),
                framework: ComplianceFramework::Gdpr,
            },
            framework: ComplianceFramework::Gdpr,
            platform_feature: "Encryption".into(),
            check_id: Some("check-encryption-at-rest".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["encryption_config".into()],
            implementation_notes: "AES-256 encryption and data masking".into(),
        },
        ControlMapping {
            control: Control {
                id: "Art.32(1)(b)".into(),
                name: "Confidentiality and Integrity".into(),
                description: "Ability to ensure ongoing confidentiality, integrity, availability, and resilience".into(),
                category: "Security of Processing".into(),
                framework: ComplianceFramework::Gdpr,
            },
            framework: ComplianceFramework::Gdpr,
            platform_feature: "Security Stack".into(),
            check_id: Some("gdpr-32-1-b".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["security_config".into()],
            implementation_notes: "Comprehensive security controls".into(),
        },
        ControlMapping {
            control: Control {
                id: "Art.32(1)(c)".into(),
                name: "Restore Availability".into(),
                description: "Ability to restore availability and access to personal data in timely manner".into(),
                category: "Security of Processing".into(),
                framework: ComplianceFramework::Gdpr,
            },
            framework: ComplianceFramework::Gdpr,
            platform_feature: "Backup".into(),
            check_id: Some("check-backup".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["backup_config".into(), "recovery_tests".into()],
            implementation_notes: "Daily backups with tested recovery".into(),
        },
        ControlMapping {
            control: Control {
                id: "Art.32(1)(d)".into(),
                name: "Testing and Evaluation".into(),
                description: "Regular testing, assessing, and evaluating effectiveness of security measures".into(),
                category: "Security of Processing".into(),
                framework: ComplianceFramework::Gdpr,
            },
            framework: ComplianceFramework::Gdpr,
            platform_feature: "Vulnerability Scanner".into(),
            check_id: Some("check-vuln-scan".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["scan_results".into(), "pentest_report".into()],
            implementation_notes: "Continuous security testing".into(),
        },
        // Article 30 - Records of Processing
        ControlMapping {
            control: Control {
                id: "Art.30".into(),
                name: "Records of Processing Activities".into(),
                description: "Maintain record of processing activities".into(),
                category: "Accountability".into(),
                framework: ComplianceFramework::Gdpr,
            },
            framework: ComplianceFramework::Gdpr,
            platform_feature: "Data Catalog".into(),
            check_id: Some("gdpr-art-30".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["processing_records".into()],
            implementation_notes: "ROPA maintained in compliance portal".into(),
        },
        // Article 33 - Breach Notification
        ControlMapping {
            control: Control {
                id: "Art.33".into(),
                name: "Breach Notification".into(),
                description: "Notify supervisory authority within 72 hours of becoming aware of breach".into(),
                category: "Breach Response".into(),
                framework: ComplianceFramework::Gdpr,
            },
            framework: ComplianceFramework::Gdpr,
            platform_feature: "Incident Response".into(),
            check_id: Some("gdpr-art-33".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["incident_procedure".into()],
            implementation_notes: "Automated breach detection and notification workflow".into(),
        },
        // Article 17 - Right to Erasure
        ControlMapping {
            control: Control {
                id: "Art.17".into(),
                name: "Right to Erasure".into(),
                description: "Data subjects have right to obtain erasure of personal data".into(),
                category: "Data Subject Rights".into(),
                framework: ComplianceFramework::Gdpr,
            },
            framework: ComplianceFramework::Gdpr,
            platform_feature: "Data Deletion".into(),
            check_id: Some("gdpr-art-17".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["deletion_procedure".into(), "deletion_logs".into()],
            implementation_notes: "Automated data subject erasure workflow".into(),
        },
    ]
}
