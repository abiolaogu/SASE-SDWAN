//! Enhanced Trust Evaluation Engine
//!
//! Continuous trust evaluation with behavioral analysis.

use crate::{Identity, Device, AccessContext, TrustLevel, RiskSignal, RiskSeverity};
use std::collections::HashMap;

/// Continuous trust evaluation engine
pub struct EnhancedTrustEngine {
    identity_verifier: IdentityVerifier,
    posture_assessor: PostureAssessor,
    context_analyzer: ContextAnalyzer,
    behavior_analyzer: BehaviorAnalyzer,
    idp_trust_levels: HashMap<String, f64>,
}

/// Trust context for evaluation
#[derive(Clone)]
pub struct TrustContext {
    // Identity
    pub user_id: String,
    pub authentication_method: AuthMethod,
    pub authentication_time: chrono::DateTime<chrono::Utc>,
    pub identity_provider: String,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    
    // Device
    pub device_id: String,
    pub device_posture: EnhancedDevicePosture,
    pub device_trust_level: TrustLevel,
    
    // Context
    pub source_ip: std::net::IpAddr,
    pub geo_location: Option<GeoLocation>,
    pub network_type: NetworkType,
    pub access_time: chrono::DateTime<chrono::Utc>,
    pub requested_resource: String,
    
    // Risk signals
    pub risk_signals: Vec<RiskSignal>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    PasswordOnly,
    PasswordMfa,
    Passwordless(PasswordlessMethod),
    Certificate,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PasswordlessMethod {
    Fido2,
    Biometric,
    MagicLink,
    Push,
}

#[derive(Clone)]
pub struct GeoLocation {
    pub country_code: String,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Corporate,
    Home,
    PublicWifi,
    Cellular,
    Vpn,
    Tor,
    Unknown,
}

/// Trust score with breakdown
#[derive(Clone)]
pub struct TrustScore {
    pub overall: f64,
    pub identity: f64,
    pub device: f64,
    pub context: f64,
    pub behavior: f64,
    pub factors: Vec<TrustFactor>,
    pub calculated_at: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct TrustFactor {
    pub name: String,
    pub category: TrustCategory,
    pub score_impact: f64,
    pub description: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustCategory {
    Identity,
    Device,
    Context,
    Behavior,
}

struct IdentityVerifier;
struct PostureAssessor;
struct ContextAnalyzer;
struct BehaviorAnalyzer {
    user_baselines: dashmap::DashMap<String, UserBaseline>,
}

#[derive(Clone, Default)]
struct UserBaseline {
    typical_hours: Option<(u8, u8)>,
    typical_locations: Vec<String>,
    typical_devices: Vec<String>,
    access_patterns: Vec<AccessPattern>,
}

#[derive(Clone)]
struct AccessPattern {
    resource: String,
    frequency: u32,
    last_access: chrono::DateTime<chrono::Utc>,
}

impl EnhancedTrustEngine {
    pub fn new() -> Self {
        let mut idp_trust = HashMap::new();
        idp_trust.insert("azure_ad".to_string(), 0.95);
        idp_trust.insert("okta".to_string(), 0.95);
        idp_trust.insert("google".to_string(), 0.90);
        idp_trust.insert("local".to_string(), 0.80);
        
        Self {
            identity_verifier: IdentityVerifier,
            posture_assessor: PostureAssessor,
            context_analyzer: ContextAnalyzer,
            behavior_analyzer: BehaviorAnalyzer {
                user_baselines: dashmap::DashMap::new(),
            },
            idp_trust_levels: idp_trust,
        }
    }
    
    /// Calculate trust score for access request
    pub async fn evaluate(&self, context: &TrustContext) -> TrustScore {
        let mut factors = Vec::new();
        
        // 1. Identity verification (30% weight)
        let identity_score = self.evaluate_identity(context, &mut factors).await;
        
        // 2. Device posture (30% weight)
        let device_score = self.evaluate_device(context, &mut factors).await;
        
        // 3. Context analysis (20% weight)
        let context_score = self.evaluate_context(context, &mut factors).await;
        
        // 4. Behavioral analysis (20% weight)
        let behavior_score = self.evaluate_behavior(context, &mut factors).await;
        
        // Calculate weighted overall score
        let overall = (identity_score * 0.30) +
                     (device_score * 0.30) +
                     (context_score * 0.20) +
                     (behavior_score * 0.20);
        
        // Apply risk signal penalties
        let risk_penalty = self.calculate_risk_penalty(&context.risk_signals);
        let final_score = (overall - risk_penalty).max(0.0);
        
        TrustScore {
            overall: final_score,
            identity: identity_score,
            device: device_score,
            context: context_score,
            behavior: behavior_score,
            factors,
            calculated_at: chrono::Utc::now(),
            valid_until: chrono::Utc::now() + chrono::Duration::minutes(5),
        }
    }
    
    async fn evaluate_identity(&self, context: &TrustContext, factors: &mut Vec<TrustFactor>) -> f64 {
        let mut score = 50.0;
        
        // Authentication method strength
        let auth_impact = match context.authentication_method {
            AuthMethod::PasswordOnly => {
                factors.push(TrustFactor {
                    name: "weak_auth".to_string(),
                    category: TrustCategory::Identity,
                    score_impact: -20.0,
                    description: "Password-only authentication".to_string(),
                });
                -20.0
            }
            AuthMethod::PasswordMfa => {
                factors.push(TrustFactor {
                    name: "mfa_enabled".to_string(),
                    category: TrustCategory::Identity,
                    score_impact: 15.0,
                    description: "MFA with TOTP enabled".to_string(),
                });
                15.0
            }
            AuthMethod::Passwordless(method) => {
                match method {
                    PasswordlessMethod::Fido2 => {
                        factors.push(TrustFactor {
                            name: "fido2".to_string(),
                            category: TrustCategory::Identity,
                            score_impact: 30.0,
                            description: "FIDO2/WebAuthn authentication".to_string(),
                        });
                        30.0
                    }
                    PasswordlessMethod::Biometric => {
                        factors.push(TrustFactor {
                            name: "biometric".to_string(),
                            category: TrustCategory::Identity,
                            score_impact: 25.0,
                            description: "Biometric authentication".to_string(),
                        });
                        25.0
                    }
                    _ => 10.0,
                }
            }
            AuthMethod::Certificate => {
                factors.push(TrustFactor {
                    name: "cert_auth".to_string(),
                    category: TrustCategory::Identity,
                    score_impact: 25.0,
                    description: "Certificate-based authentication".to_string(),
                });
                25.0
            }
        };
        score += auth_impact;
        
        // Authentication freshness
        let auth_age = chrono::Utc::now() - context.authentication_time;
        if auth_age > chrono::Duration::hours(8) {
            factors.push(TrustFactor {
                name: "stale_auth".to_string(),
                category: TrustCategory::Identity,
                score_impact: -10.0,
                description: "Authentication older than 8 hours".to_string(),
            });
            score -= 10.0;
        }
        
        // IdP trust level
        let idp_trust = self.idp_trust_levels
            .get(&context.identity_provider)
            .copied()
            .unwrap_or(0.7);
        
        if idp_trust < 0.8 {
            factors.push(TrustFactor {
                name: "untrusted_idp".to_string(),
                category: TrustCategory::Identity,
                score_impact: -15.0,
                description: "Identity provider has reduced trust".to_string(),
            });
            score -= 15.0;
        }
        
        score.clamp(0.0, 100.0)
    }
    
    async fn evaluate_device(&self, context: &TrustContext, factors: &mut Vec<TrustFactor>) -> f64 {
        let posture = &context.device_posture;
        let mut score = 50.0;
        
        // Management status
        match posture.management_status {
            ManagementStatus::FullyManaged => {
                factors.push(TrustFactor {
                    name: "managed_device".to_string(),
                    category: TrustCategory::Device,
                    score_impact: 25.0,
                    description: "Fully managed corporate device".to_string(),
                });
                score += 25.0;
            }
            ManagementStatus::PartiallyManaged => {
                factors.push(TrustFactor {
                    name: "partial_managed".to_string(),
                    category: TrustCategory::Device,
                    score_impact: 10.0,
                    description: "BYOD with MDM".to_string(),
                });
                score += 10.0;
            }
            ManagementStatus::Unmanaged => {
                factors.push(TrustFactor {
                    name: "unmanaged".to_string(),
                    category: TrustCategory::Device,
                    score_impact: -20.0,
                    description: "Unmanaged device".to_string(),
                });
                score -= 20.0;
            }
        }
        
        // Security software
        if !posture.antivirus_active {
            factors.push(TrustFactor {
                name: "no_av".to_string(),
                category: TrustCategory::Device,
                score_impact: -15.0,
                description: "No active antivirus".to_string(),
            });
            score -= 15.0;
        }
        
        if !posture.firewall_enabled {
            factors.push(TrustFactor {
                name: "no_fw".to_string(),
                category: TrustCategory::Device,
                score_impact: -10.0,
                description: "Firewall disabled".to_string(),
            });
            score -= 10.0;
        }
        
        // Encryption
        if !posture.disk_encrypted {
            factors.push(TrustFactor {
                name: "no_encryption".to_string(),
                category: TrustCategory::Device,
                score_impact: -15.0,
                description: "Disk not encrypted".to_string(),
            });
            score -= 15.0;
        }
        
        // Patch status
        if posture.os_patch_age_days > 30 {
            factors.push(TrustFactor {
                name: "outdated_os".to_string(),
                category: TrustCategory::Device,
                score_impact: -20.0,
                description: format!("OS {} days old", posture.os_patch_age_days),
            });
            score -= 20.0;
        } else if posture.os_patch_age_days > 14 {
            score -= 10.0;
        }
        
        // Jailbreak/root
        if posture.is_jailbroken || posture.is_rooted {
            factors.push(TrustFactor {
                name: "jailbroken".to_string(),
                category: TrustCategory::Device,
                score_impact: -40.0,
                description: "Device is jailbroken/rooted".to_string(),
            });
            score -= 40.0;
        }
        
        // Screen lock
        if !posture.screen_lock_enabled {
            score -= 10.0;
        }
        
        score.clamp(0.0, 100.0)
    }
    
    async fn evaluate_context(&self, context: &TrustContext, factors: &mut Vec<TrustFactor>) -> f64 {
        let mut score = 70.0;
        
        // Network type
        match context.network_type {
            NetworkType::Corporate => {
                factors.push(TrustFactor {
                    name: "corporate_network".to_string(),
                    category: TrustCategory::Context,
                    score_impact: 15.0,
                    description: "Corporate network".to_string(),
                });
                score += 15.0;
            }
            NetworkType::Home => {}
            NetworkType::PublicWifi => {
                factors.push(TrustFactor {
                    name: "public_wifi".to_string(),
                    category: TrustCategory::Context,
                    score_impact: -15.0,
                    description: "Public WiFi".to_string(),
                });
                score -= 15.0;
            }
            NetworkType::Cellular => {
                score -= 5.0;
            }
            NetworkType::Vpn => {
                factors.push(TrustFactor {
                    name: "vpn_detected".to_string(),
                    category: TrustCategory::Context,
                    score_impact: -10.0,
                    description: "VPN/proxy detected".to_string(),
                });
                score -= 10.0;
            }
            NetworkType::Tor => {
                factors.push(TrustFactor {
                    name: "tor_detected".to_string(),
                    category: TrustCategory::Context,
                    score_impact: -40.0,
                    description: "Tor exit node".to_string(),
                });
                score -= 40.0;
            }
            NetworkType::Unknown => {
                score -= 10.0;
            }
        }
        
        // Time-based
        let hour = context.access_time.time().hour();
        let weekday = context.access_time.weekday();
        let is_weekend = weekday == chrono::Weekday::Sat || weekday == chrono::Weekday::Sun;
        
        if (hour < 6 || hour > 22) && !is_weekend {
            factors.push(TrustFactor {
                name: "unusual_hours".to_string(),
                category: TrustCategory::Context,
                score_impact: -10.0,
                description: "Unusual access hours".to_string(),
            });
            score -= 10.0;
        }
        
        score.clamp(0.0, 100.0)
    }
    
    async fn evaluate_behavior(&self, context: &TrustContext, factors: &mut Vec<TrustFactor>) -> f64 {
        let mut score = 80.0;
        
        // Get user baseline
        let baseline = self.behavior_analyzer.user_baselines
            .get(&context.user_id)
            .map(|b| b.clone())
            .unwrap_or_default();
        
        // Check if device is known
        if !baseline.typical_devices.contains(&context.device_id) {
            factors.push(TrustFactor {
                name: "new_device".to_string(),
                category: TrustCategory::Behavior,
                score_impact: -10.0,
                description: "New device for user".to_string(),
            });
            score -= 10.0;
        }
        
        // Check location
        if let Some(geo) = &context.geo_location {
            if !baseline.typical_locations.contains(&geo.country_code) {
                factors.push(TrustFactor {
                    name: "new_location".to_string(),
                    category: TrustCategory::Behavior,
                    score_impact: -15.0,
                    description: format!("New location: {}", geo.country_code),
                });
                score -= 15.0;
            }
        }
        
        score.clamp(0.0, 100.0)
    }
    
    fn calculate_risk_penalty(&self, signals: &[RiskSignal]) -> f64 {
        signals.iter().map(|s| {
            match s.severity {
                RiskSeverity::Low => 5.0,
                RiskSeverity::Medium => 15.0,
                RiskSeverity::High => 30.0,
                RiskSeverity::Critical => 50.0,
            }
        }).sum()
    }
    
    /// Update user baseline
    pub fn update_baseline(&self, user_id: &str, context: &TrustContext) {
        self.behavior_analyzer.user_baselines
            .entry(user_id.to_string())
            .and_modify(|b| {
                if !b.typical_devices.contains(&context.device_id) {
                    b.typical_devices.push(context.device_id.clone());
                }
                if let Some(geo) = &context.geo_location {
                    if !b.typical_locations.contains(&geo.country_code) {
                        b.typical_locations.push(geo.country_code.clone());
                    }
                }
            })
            .or_insert_with(|| UserBaseline {
                typical_devices: vec![context.device_id.clone()],
                typical_locations: context.geo_location.as_ref()
                    .map(|g| vec![g.country_code.clone()])
                    .unwrap_or_default(),
                ..Default::default()
            });
    }
}

impl Default for EnhancedTrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

// Enhanced device posture
#[derive(Clone)]
pub struct EnhancedDevicePosture {
    pub platform: Platform,
    pub os_version: String,
    pub management_status: ManagementStatus,
    pub mdm_enrolled: bool,
    pub mdm_compliant: bool,
    pub antivirus_active: bool,
    pub antivirus_name: Option<String>,
    pub firewall_enabled: bool,
    pub edr_installed: bool,
    pub disk_encrypted: bool,
    pub os_patch_age_days: u32,
    pub screen_lock_enabled: bool,
    pub screen_lock_timeout_secs: Option<u32>,
    pub is_jailbroken: bool,
    pub is_rooted: bool,
    pub developer_mode: bool,
    pub client_certificate_valid: bool,
    pub hardware_attestation: Option<HardwareAttestation>,
    pub collected_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    MacOS,
    Linux,
    iOS,
    Android,
    ChromeOS,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ManagementStatus {
    FullyManaged,
    PartiallyManaged,
    Unmanaged,
}

#[derive(Clone)]
pub struct HardwareAttestation {
    pub valid: bool,
    pub tpm_version: Option<String>,
    pub secure_boot: bool,
}

use chrono::{Datelike, Timelike};
