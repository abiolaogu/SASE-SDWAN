//! Device Posture Assessment
//!
//! Comprehensive device posture checking and compliance.

use crate::trust_engine::{EnhancedDevicePosture, ManagementStatus};
use std::time::Duration;

/// Comprehensive device posture assessor
pub struct PostureAssessor {
    posture_rules: Vec<PostureRule>,
    compliance_policies: dashmap::DashMap<String, PosturePolicy>,
}

#[derive(Clone)]
pub struct PostureRule {
    pub id: String,
    pub name: String,
    pub requirement: PostureRequirement,
    pub severity: RuleSeverity,
    pub remediation: String,
}

#[derive(Clone)]
pub enum PostureRequirement {
    OsVersion { min_version: String },
    DiskEncryption,
    Antivirus,
    Firewall,
    ScreenLock { max_timeout_secs: u32 },
    NotJailbroken,
    MdmEnrolled,
    CertificateValid,
    NoProhibitedApps { apps: Vec<String> },
    PatchAge { max_days: u32 },
    EdrInstalled,
    SecureBoot,
}

#[derive(Clone, Copy)]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone)]
pub struct PosturePolicy {
    pub id: String,
    pub name: String,
    pub requirements: Vec<PostureRequirement>,
    pub min_score: f64,
}

#[derive(Clone)]
pub struct PostureAssessment {
    pub compliant: bool,
    pub score: f64,
    pub violations: Vec<PostureViolation>,
    pub recommendations: Vec<String>,
}

#[derive(Clone)]
pub struct PostureViolation {
    pub requirement: String,
    pub current_state: String,
    pub remediation: String,
    pub score_penalty: f64,
}

impl PostureAssessor {
    pub fn new() -> Self {
        let mut assessor = Self {
            posture_rules: Vec::new(),
            compliance_policies: dashmap::DashMap::new(),
        };
        
        assessor.load_default_rules();
        assessor
    }
    
    fn load_default_rules(&mut self) {
        self.posture_rules = vec![
            PostureRule {
                id: "disk_encryption".to_string(),
                name: "Disk Encryption".to_string(),
                requirement: PostureRequirement::DiskEncryption,
                severity: RuleSeverity::High,
                remediation: "Enable full disk encryption (BitLocker/FileVault)".to_string(),
            },
            PostureRule {
                id: "antivirus".to_string(),
                name: "Antivirus Active".to_string(),
                requirement: PostureRequirement::Antivirus,
                severity: RuleSeverity::High,
                remediation: "Install and enable antivirus software".to_string(),
            },
            PostureRule {
                id: "firewall".to_string(),
                name: "Firewall Enabled".to_string(),
                requirement: PostureRequirement::Firewall,
                severity: RuleSeverity::Medium,
                remediation: "Enable system firewall".to_string(),
            },
            PostureRule {
                id: "screen_lock".to_string(),
                name: "Screen Lock".to_string(),
                requirement: PostureRequirement::ScreenLock { max_timeout_secs: 300 },
                severity: RuleSeverity::Medium,
                remediation: "Enable screen lock with 5 minute timeout".to_string(),
            },
            PostureRule {
                id: "not_jailbroken".to_string(),
                name: "Not Jailbroken".to_string(),
                requirement: PostureRequirement::NotJailbroken,
                severity: RuleSeverity::Critical,
                remediation: "Device must not be jailbroken or rooted".to_string(),
            },
            PostureRule {
                id: "patch_age".to_string(),
                name: "OS Patches".to_string(),
                requirement: PostureRequirement::PatchAge { max_days: 30 },
                severity: RuleSeverity::High,
                remediation: "Install OS security updates".to_string(),
            },
        ];
    }
    
    /// Assess device posture against policy
    pub fn assess(&self, posture: &EnhancedDevicePosture, policy_id: &str) -> PostureAssessment {
        let policy = self.compliance_policies.get(policy_id);
        let requirements: Vec<_> = policy
            .map(|p| p.requirements.clone())
            .unwrap_or_else(|| self.posture_rules.iter().map(|r| r.requirement.clone()).collect());
        
        let mut assessment = PostureAssessment {
            compliant: true,
            score: 100.0,
            violations: Vec::new(),
            recommendations: Vec::new(),
        };
        
        for requirement in &requirements {
            let result = self.check_requirement(posture, requirement);
            
            if !result.met {
                assessment.compliant = false;
                assessment.score -= result.score_penalty;
                assessment.violations.push(PostureViolation {
                    requirement: result.requirement_name,
                    current_state: result.current_state,
                    remediation: result.remediation,
                    score_penalty: result.score_penalty,
                });
            }
        }
        
        assessment.score = assessment.score.max(0.0);
        assessment.recommendations = self.generate_recommendations(posture);
        
        assessment
    }
    
    fn check_requirement(&self, posture: &EnhancedDevicePosture, req: &PostureRequirement) -> RequirementResult {
        match req {
            PostureRequirement::OsVersion { min_version } => {
                let met = version_compare(&posture.os_version, min_version) >= 0;
                RequirementResult {
                    met,
                    requirement_name: "OS Version".to_string(),
                    score_penalty: if met { 0.0 } else { 15.0 },
                    current_state: posture.os_version.clone(),
                    remediation: format!("Upgrade to OS version {}", min_version),
                }
            }
            
            PostureRequirement::DiskEncryption => {
                RequirementResult {
                    met: posture.disk_encrypted,
                    requirement_name: "Disk Encryption".to_string(),
                    score_penalty: if posture.disk_encrypted { 0.0 } else { 20.0 },
                    current_state: posture.disk_encrypted.to_string(),
                    remediation: "Enable full disk encryption".to_string(),
                }
            }
            
            PostureRequirement::Antivirus => {
                RequirementResult {
                    met: posture.antivirus_active,
                    requirement_name: "Antivirus".to_string(),
                    score_penalty: if posture.antivirus_active { 0.0 } else { 20.0 },
                    current_state: posture.antivirus_active.to_string(),
                    remediation: "Install and enable antivirus".to_string(),
                }
            }
            
            PostureRequirement::Firewall => {
                RequirementResult {
                    met: posture.firewall_enabled,
                    requirement_name: "Firewall".to_string(),
                    score_penalty: if posture.firewall_enabled { 0.0 } else { 15.0 },
                    current_state: posture.firewall_enabled.to_string(),
                    remediation: "Enable system firewall".to_string(),
                }
            }
            
            PostureRequirement::ScreenLock { max_timeout_secs } => {
                let met = posture.screen_lock_enabled &&
                    posture.screen_lock_timeout_secs
                        .map(|t| t <= *max_timeout_secs)
                        .unwrap_or(false);
                RequirementResult {
                    met,
                    requirement_name: "Screen Lock".to_string(),
                    score_penalty: if met { 0.0 } else { 10.0 },
                    current_state: format!(
                        "Enabled: {}, Timeout: {:?}s",
                        posture.screen_lock_enabled,
                        posture.screen_lock_timeout_secs
                    ),
                    remediation: format!("Set screen lock timeout to {}s or less", max_timeout_secs),
                }
            }
            
            PostureRequirement::NotJailbroken => {
                let met = !posture.is_jailbroken && !posture.is_rooted;
                RequirementResult {
                    met,
                    requirement_name: "Not Jailbroken".to_string(),
                    score_penalty: if met { 0.0 } else { 50.0 },
                    current_state: format!("Jailbroken: {}, Rooted: {}", posture.is_jailbroken, posture.is_rooted),
                    remediation: "Device must not be jailbroken or rooted".to_string(),
                }
            }
            
            PostureRequirement::MdmEnrolled => {
                RequirementResult {
                    met: posture.mdm_enrolled,
                    requirement_name: "MDM Enrolled".to_string(),
                    score_penalty: if posture.mdm_enrolled { 0.0 } else { 25.0 },
                    current_state: posture.mdm_enrolled.to_string(),
                    remediation: "Enroll device in MDM".to_string(),
                }
            }
            
            PostureRequirement::CertificateValid => {
                RequirementResult {
                    met: posture.client_certificate_valid,
                    requirement_name: "Certificate Valid".to_string(),
                    score_penalty: if posture.client_certificate_valid { 0.0 } else { 20.0 },
                    current_state: posture.client_certificate_valid.to_string(),
                    remediation: "Install valid client certificate".to_string(),
                }
            }
            
            PostureRequirement::NoProhibitedApps { apps: _ } => {
                // In production: check installed apps
                RequirementResult {
                    met: true,
                    requirement_name: "No Prohibited Apps".to_string(),
                    score_penalty: 0.0,
                    current_state: "Clean".to_string(),
                    remediation: "Remove prohibited applications".to_string(),
                }
            }
            
            PostureRequirement::PatchAge { max_days } => {
                let met = posture.os_patch_age_days <= *max_days;
                RequirementResult {
                    met,
                    requirement_name: "Patch Age".to_string(),
                    score_penalty: if met { 0.0 } else { 15.0 },
                    current_state: format!("{} days", posture.os_patch_age_days),
                    remediation: format!("Install updates within {} days", max_days),
                }
            }
            
            PostureRequirement::EdrInstalled => {
                RequirementResult {
                    met: posture.edr_installed,
                    requirement_name: "EDR Installed".to_string(),
                    score_penalty: if posture.edr_installed { 0.0 } else { 15.0 },
                    current_state: posture.edr_installed.to_string(),
                    remediation: "Install EDR agent".to_string(),
                }
            }
            
            PostureRequirement::SecureBoot => {
                let met = posture.hardware_attestation
                    .as_ref()
                    .map(|h| h.secure_boot)
                    .unwrap_or(false);
                RequirementResult {
                    met,
                    requirement_name: "Secure Boot".to_string(),
                    score_penalty: if met { 0.0 } else { 10.0 },
                    current_state: met.to_string(),
                    remediation: "Enable Secure Boot in BIOS".to_string(),
                }
            }
        }
    }
    
    fn generate_recommendations(&self, posture: &EnhancedDevicePosture) -> Vec<String> {
        let mut recs = Vec::new();
        
        if !posture.edr_installed {
            recs.push("Consider installing EDR for enhanced protection".to_string());
        }
        
        if posture.hardware_attestation.is_none() {
            recs.push("Enable hardware attestation for stronger security".to_string());
        }
        
        if posture.os_patch_age_days > 7 {
            recs.push("Enable automatic security updates".to_string());
        }
        
        recs
    }
    
    /// Add compliance policy
    pub fn add_policy(&self, policy: PosturePolicy) {
        self.compliance_policies.insert(policy.id.clone(), policy);
    }
}

impl Default for PostureAssessor {
    fn default() -> Self {
        Self::new()
    }
}

struct RequirementResult {
    met: bool,
    requirement_name: String,
    score_penalty: f64,
    current_state: String,
    remediation: String,
}

fn version_compare(a: &str, b: &str) -> i32 {
    let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
    let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();
    
    for i in 0..a_parts.len().max(b_parts.len()) {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        if av > bv { return 1; }
        if av < bv { return -1; }
    }
    0
}
