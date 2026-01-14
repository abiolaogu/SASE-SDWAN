//! SOC 2 Type II Framework

use super::{Control, ControlMapping, ComplianceFramework};
use crate::checks::ComplianceStatus;

/// Get SOC 2 control mappings
pub fn get_mappings() -> Vec<ControlMapping> {
    vec![
        // CC1 - Control Environment
        ControlMapping {
            control: Control {
                id: "CC1.1".into(),
                name: "Security Policies".into(),
                description: "The entity has defined security policies".into(),
                category: "Control Environment".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "Policy Engine".into(),
            check_id: Some("soc2-cc1-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["policy_document".into(), "approval_record".into()],
            implementation_notes: "Security policies managed in compliance portal".into(),
        },
        // CC2 - Communication and Information
        ControlMapping {
            control: Control {
                id: "CC2.1".into(),
                name: "Security Awareness".into(),
                description: "Security awareness training provided to personnel".into(),
                category: "Communication".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "Training Module".into(),
            check_id: Some("soc2-cc2-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["training_completion".into()],
            implementation_notes: "Training tracked per user".into(),
        },
        // CC5 - Logical and Physical Access Controls
        ControlMapping {
            control: Control {
                id: "CC5.1".into(),
                name: "Logical Access Controls".into(),
                description: "Logical access to systems is restricted".into(),
                category: "Access Control".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "RBAC".into(),
            check_id: Some("soc2-cc5-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["access_logs".into(), "rbac_config".into()],
            implementation_notes: "Role-based access control enforced".into(),
        },
        ControlMapping {
            control: Control {
                id: "CC5.2".into(),
                name: "Multi-Factor Authentication".into(),
                description: "MFA required for all administrative access".into(),
                category: "Access Control".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "MFA".into(),
            check_id: Some("soc2-cc5-2-mfa".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["mfa_enrollment".into(), "auth_logs".into()],
            implementation_notes: "MFA enforced for admin and user access".into(),
        },
        // CC6 - System Operations
        ControlMapping {
            control: Control {
                id: "CC6.1".into(),
                name: "Encryption in Transit".into(),
                description: "Data is encrypted during transmission".into(),
                category: "System Operations".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "TLS Everywhere".into(),
            check_id: Some("check-tls-enabled".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["tls_config".into(), "scan_results".into()],
            implementation_notes: "TLS 1.2+ enforced on all connections".into(),
        },
        ControlMapping {
            control: Control {
                id: "CC6.2".into(),
                name: "Encryption at Rest".into(),
                description: "Data is encrypted when stored".into(),
                category: "System Operations".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "Disk Encryption".into(),
            check_id: Some("check-encryption-at-rest".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["encryption_config".into()],
            implementation_notes: "AES-256 encryption on all storage".into(),
        },
        // CC7 - Change Management
        ControlMapping {
            control: Control {
                id: "CC7.1".into(),
                name: "Change Management".into(),
                description: "Changes are authorized before implementation".into(),
                category: "Change Management".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "Audit Trail".into(),
            check_id: Some("soc2-cc7-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["change_logs".into(), "approval_records".into()],
            implementation_notes: "All changes logged in immutable audit trail".into(),
        },
        // CC8 - Risk Mitigation
        ControlMapping {
            control: Control {
                id: "CC8.1".into(),
                name: "Vulnerability Management".into(),
                description: "Vulnerabilities are identified and remediated".into(),
                category: "Risk Mitigation".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "Vulnerability Scanner".into(),
            check_id: Some("check-vuln-scan".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["scan_results".into(), "remediation_records".into()],
            implementation_notes: "Weekly vulnerability scans with 30-day SLA".into(),
        },
        // CC9 - Availability
        ControlMapping {
            control: Control {
                id: "CC9.1".into(),
                name: "Backup and Recovery".into(),
                description: "Backups are performed and tested".into(),
                category: "Availability".into(),
                framework: ComplianceFramework::Soc2TypeII,
            },
            framework: ComplianceFramework::Soc2TypeII,
            platform_feature: "Backup System".into(),
            check_id: Some("check-backup".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["backup_logs".into(), "recovery_tests".into()],
            implementation_notes: "Daily backups with quarterly recovery tests".into(),
        },
    ]
}
