//! ISO 27001:2022 Framework

use super::{Control, ControlMapping, ComplianceFramework};
use crate::checks::ComplianceStatus;

/// Get ISO 27001 control mappings
pub fn get_mappings() -> Vec<ControlMapping> {
    vec![
        // A.5 - Organizational Controls
        ControlMapping {
            control: Control {
                id: "A.5.1".into(),
                name: "Information Security Policies".into(),
                description: "Policies for information security shall be defined and approved".into(),
                category: "Organizational".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "Policy Engine".into(),
            check_id: Some("iso-a5-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["policy_document".into()],
            implementation_notes: "Policies managed in compliance portal".into(),
        },
        // A.6 - People Controls
        ControlMapping {
            control: Control {
                id: "A.6.3".into(),
                name: "Information Security Awareness".into(),
                description: "Personnel shall receive appropriate security awareness".into(),
                category: "People".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "Training Module".into(),
            check_id: Some("iso-a6-3".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["training_records".into()],
            implementation_notes: "Annual security awareness training".into(),
        },
        // A.8 - Technological Controls
        ControlMapping {
            control: Control {
                id: "A.8.1".into(),
                name: "User Endpoint Devices".into(),
                description: "Information on user endpoint devices shall be protected".into(),
                category: "Technological".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "Device Posture".into(),
            check_id: Some("check-device-posture".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["posture_reports".into()],
            implementation_notes: "Device posture enforced via OSC client".into(),
        },
        ControlMapping {
            control: Control {
                id: "A.8.5".into(),
                name: "Secure Authentication".into(),
                description: "Secure authentication technologies shall be implemented".into(),
                category: "Technological".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "MFA".into(),
            check_id: Some("check-mfa".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["mfa_config".into()],
            implementation_notes: "MFA with TOTP/WebAuthn".into(),
        },
        ControlMapping {
            control: Control {
                id: "A.8.9".into(),
                name: "Configuration Management".into(),
                description: "Configurations shall be established, documented, and maintained".into(),
                category: "Technological".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "Configuration Management".into(),
            check_id: Some("iso-a8-9".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["config_snapshots".into()],
            implementation_notes: "Configuration versioned and audited".into(),
        },
        ControlMapping {
            control: Control {
                id: "A.8.10".into(),
                name: "Information Deletion".into(),
                description: "Information shall be deleted when no longer required".into(),
                category: "Technological".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "Data Retention".into(),
            check_id: Some("iso-a8-10".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["retention_policy".into(), "deletion_logs".into()],
            implementation_notes: "Automated data retention policies".into(),
        },
        ControlMapping {
            control: Control {
                id: "A.8.12".into(),
                name: "Data Leakage Prevention".into(),
                description: "Data leakage prevention measures shall be applied".into(),
                category: "Technological".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "DLP".into(),
            check_id: Some("check-dlp".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["dlp_config".into(), "dlp_alerts".into()],
            implementation_notes: "DLP policies for sensitive data".into(),
        },
        ControlMapping {
            control: Control {
                id: "A.8.15".into(),
                name: "Logging".into(),
                description: "Logs shall record activities, exceptions, and security events".into(),
                category: "Technological".into(),
                framework: ComplianceFramework::Iso27001_2022,
            },
            framework: ComplianceFramework::Iso27001_2022,
            platform_feature: "Audit Trail".into(),
            check_id: Some("check-logging".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["log_config".into(), "log_samples".into()],
            implementation_notes: "Comprehensive logging with hash chain".into(),
        },
    ]
}
