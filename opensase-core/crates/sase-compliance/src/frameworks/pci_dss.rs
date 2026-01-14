//! PCI-DSS 4.0 Framework

use super::{Control, ControlMapping, ComplianceFramework};
use crate::checks::ComplianceStatus;

/// Get PCI-DSS control mappings
pub fn get_mappings() -> Vec<ControlMapping> {
    vec![
        // Requirement 1 - Network Security Controls
        ControlMapping {
            control: Control {
                id: "1.2.1".into(),
                name: "Firewall Configuration".into(),
                description: "Network security controls are configured and maintained".into(),
                category: "Network Security".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "Firewall".into(),
            check_id: Some("pci-1-2-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["firewall_rules".into()],
            implementation_notes: "Zone-based firewall on all edges".into(),
        },
        // Requirement 2 - Secure Configurations
        ControlMapping {
            control: Control {
                id: "2.2.1".into(),
                name: "System Hardening".into(),
                description: "System components are hardened".into(),
                category: "Secure Configuration".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "Hardening".into(),
            check_id: Some("pci-2-2-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["hardening_config".into()],
            implementation_notes: "CIS benchmarks applied".into(),
        },
        // Requirement 3 - Protect Stored Account Data
        ControlMapping {
            control: Control {
                id: "3.5.1".into(),
                name: "Encryption of Stored Data".into(),
                description: "PAN is encrypted when stored".into(),
                category: "Data Protection".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "Encryption at Rest".into(),
            check_id: Some("check-encryption-at-rest".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["encryption_config".into()],
            implementation_notes: "AES-256 encryption".into(),
        },
        // Requirement 4 - Protect Cardholder Data in Transit
        ControlMapping {
            control: Control {
                id: "4.2.1".into(),
                name: "Strong Cryptography in Transit".into(),
                description: "Strong cryptography protects PAN during transmission".into(),
                category: "Transmission Security".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "TLS".into(),
            check_id: Some("check-tls-enabled".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["tls_config".into()],
            implementation_notes: "TLS 1.2+ with strong ciphers".into(),
        },
        // Requirement 7 - Restrict Access
        ControlMapping {
            control: Control {
                id: "7.2.1".into(),
                name: "Access Control Model".into(),
                description: "Access control model restricts access based on need to know".into(),
                category: "Access Control".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "RBAC".into(),
            check_id: Some("pci-7-2-1".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["rbac_config".into()],
            implementation_notes: "Role-based access control".into(),
        },
        // Requirement 8 - Identify Users
        ControlMapping {
            control: Control {
                id: "8.3.1".into(),
                name: "Multi-Factor Authentication".into(),
                description: "MFA is implemented for access to CDE".into(),
                category: "Authentication".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "MFA".into(),
            check_id: Some("check-mfa".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["mfa_config".into()],
            implementation_notes: "MFA required for all CDE access".into(),
        },
        // Requirement 10 - Log and Monitor
        ControlMapping {
            control: Control {
                id: "10.2.1".into(),
                name: "Audit Logs".into(),
                description: "Audit logs are enabled for all system components".into(),
                category: "Logging".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "Audit Trail".into(),
            check_id: Some("check-logging".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["log_config".into()],
            implementation_notes: "Comprehensive audit logging".into(),
        },
        // Requirement 11 - Test Security
        ControlMapping {
            control: Control {
                id: "11.3.1".into(),
                name: "Vulnerability Scanning".into(),
                description: "Internal vulnerability scans are performed quarterly".into(),
                category: "Security Testing".into(),
                framework: ComplianceFramework::PciDss4_0,
            },
            framework: ComplianceFramework::PciDss4_0,
            platform_feature: "Vulnerability Scanner".into(),
            check_id: Some("check-vuln-scan".into()),
            status: ComplianceStatus::Compliant,
            evidence_types: vec!["scan_results".into()],
            implementation_notes: "Weekly internal + quarterly ASV scans".into(),
        },
    ]
}
