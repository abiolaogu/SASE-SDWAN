//! Device Trust Assessment
//!
//! Device posture checking and trust evaluation.

use crate::{Device, DeviceType, TrustLevel, DevicePosture, DeviceCertificate};

/// Device trust assessor
pub struct DeviceAssessor {
    /// Registered devices
    devices: dashmap::DashMap<String, DeviceRecord>,
    /// Posture requirements
    posture_requirements: PostureRequirements,
    /// Trust calculation weights
    weights: TrustWeights,
}

struct DeviceRecord {
    device: Device,
    owner_id: String,
    registered_at: chrono::DateTime<chrono::Utc>,
    last_posture_check: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct PostureRequirements {
    pub require_firewall: bool,
    pub require_antivirus: bool,
    pub require_encryption: bool,
    pub require_patched_os: bool,
    pub require_screen_lock: bool,
    pub block_jailbroken: bool,
    pub max_os_age_days: u32,
}

impl Default for PostureRequirements {
    fn default() -> Self {
        Self {
            require_firewall: true,
            require_antivirus: true,
            require_encryption: true,
            require_patched_os: true,
            require_screen_lock: true,
            block_jailbroken: true,
            max_os_age_days: 30,
        }
    }
}

#[derive(Clone)]
struct TrustWeights {
    managed: i32,
    compliant: i32,
    firewall: i32,
    antivirus: i32,
    encryption: i32,
    patched: i32,
    screen_lock: i32,
    certificate: i32,
    jailbreak_penalty: i32,
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            managed: 25,
            compliant: 20,
            firewall: 10,
            antivirus: 10,
            encryption: 15,
            patched: 10,
            screen_lock: 5,
            certificate: 15,
            jailbreak_penalty: -50,
        }
    }
}

impl DeviceAssessor {
    pub fn new() -> Self {
        Self {
            devices: dashmap::DashMap::new(),
            posture_requirements: PostureRequirements::default(),
            weights: TrustWeights::default(),
        }
    }
    
    /// Register device
    pub fn register(&self, user_id: &str, device: Device) {
        self.devices.insert(device.id.clone(), DeviceRecord {
            device,
            owner_id: user_id.to_string(),
            registered_at: chrono::Utc::now(),
            last_posture_check: chrono::Utc::now(),
        });
    }
    
    /// Check if device is registered
    pub fn is_registered(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }
    
    /// Assess device trust level
    pub fn assess(&self, device: &Device) -> TrustAssessment {
        let mut score = 0i32;
        let mut issues = Vec::new();
        
        // Check if jailbroken (immediate block)
        if device.posture.jailbroken {
            if self.posture_requirements.block_jailbroken {
                return TrustAssessment {
                    trust_level: TrustLevel::Untrusted,
                    score: 0,
                    compliant: false,
                    issues: vec!["Device is jailbroken/rooted".to_string()],
                };
            }
            score += self.weights.jailbreak_penalty;
            issues.push("Device is jailbroken/rooted".to_string());
        }
        
        // Managed device
        if device.managed {
            score += self.weights.managed;
        } else {
            issues.push("Device is not managed".to_string());
        }
        
        // Compliant
        if device.compliant {
            score += self.weights.compliant;
        }
        
        // Check posture
        let (posture_score, posture_issues) = self.check_posture(&device.posture);
        score += posture_score;
        issues.extend(posture_issues);
        
        // Check certificates
        if !device.certificates.is_empty() {
            let has_valid = device.certificates.iter().any(|c| {
                chrono::Utc::now() < c.valid_until
            });
            if has_valid {
                score += self.weights.certificate;
            } else {
                issues.push("No valid device certificate".to_string());
            }
        }
        
        // Calculate trust level
        let trust_level = if score >= 80 {
            TrustLevel::Full
        } else if score >= 60 {
            TrustLevel::High
        } else if score >= 40 {
            TrustLevel::Medium
        } else if score >= 20 {
            TrustLevel::Low
        } else {
            TrustLevel::Untrusted
        };
        
        // Determine compliance
        let compliant = self.is_compliant(&device.posture);
        
        TrustAssessment {
            trust_level,
            score: score.max(0) as u32,
            compliant,
            issues,
        }
    }
    
    fn check_posture(&self, posture: &DevicePosture) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut issues = Vec::new();
        
        if posture.firewall_enabled {
            score += self.weights.firewall;
        } else if self.posture_requirements.require_firewall {
            issues.push("Firewall is disabled".to_string());
        }
        
        if posture.antivirus_running {
            score += self.weights.antivirus;
        } else if self.posture_requirements.require_antivirus {
            issues.push("Antivirus not running".to_string());
        }
        
        if posture.disk_encrypted {
            score += self.weights.encryption;
        } else if self.posture_requirements.require_encryption {
            issues.push("Disk is not encrypted".to_string());
        }
        
        if posture.os_patched {
            score += self.weights.patched;
        } else if self.posture_requirements.require_patched_os {
            issues.push("OS is not up to date".to_string());
        }
        
        if posture.screen_lock_enabled {
            score += self.weights.screen_lock;
        } else if self.posture_requirements.require_screen_lock {
            issues.push("Screen lock is disabled".to_string());
        }
        
        (score, issues)
    }
    
    fn is_compliant(&self, posture: &DevicePosture) -> bool {
        let req = &self.posture_requirements;
        
        (!req.require_firewall || posture.firewall_enabled) &&
        (!req.require_antivirus || posture.antivirus_running) &&
        (!req.require_encryption || posture.disk_encrypted) &&
        (!req.require_patched_os || posture.os_patched) &&
        (!req.require_screen_lock || posture.screen_lock_enabled) &&
        (!req.block_jailbroken || !posture.jailbroken)
    }
    
    /// Update device posture
    pub fn update_posture(&self, device_id: &str, posture: DevicePosture) {
        if let Some(mut record) = self.devices.get_mut(device_id) {
            record.device.posture = posture;
            record.last_posture_check = chrono::Utc::now();
        }
    }
    
    /// Get user's devices
    pub fn get_user_devices(&self, user_id: &str) -> Vec<Device> {
        self.devices.iter()
            .filter(|r| r.owner_id == user_id)
            .map(|r| r.device.clone())
            .collect()
    }
}

impl Default for DeviceAssessor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TrustAssessment {
    pub trust_level: TrustLevel,
    pub score: u32,
    pub compliant: bool,
    pub issues: Vec<String>,
}
