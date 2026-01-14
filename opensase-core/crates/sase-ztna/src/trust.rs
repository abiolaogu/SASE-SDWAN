//! Trust Evaluation Engine
//!
//! Unified trust scoring combining identity, device, and context.

use crate::{Identity, Device, AccessContext, TrustLevel};

/// Trust evaluation engine
pub struct TrustEvaluationEngine {
    /// Identity weight
    identity_weight: f64,
    /// Device weight
    device_weight: f64,
    /// Context weight
    context_weight: f64,
    /// Thresholds
    thresholds: TrustThresholds,
}

#[derive(Clone)]
pub struct TrustThresholds {
    pub allow: f64,
    pub allow_with_mfa: f64,
    pub allow_with_session_record: f64,
    pub deny: f64,
}

impl Default for TrustThresholds {
    fn default() -> Self {
        Self {
            allow: 80.0,
            allow_with_mfa: 60.0,
            allow_with_session_record: 40.0,
            deny: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustEvaluation {
    pub overall_score: f64,
    pub identity_score: f64,
    pub device_score: f64,
    pub context_score: f64,
    pub trust_level: TrustLevel,
    pub factors: Vec<TrustFactor>,
    pub recommendation: TrustRecommendation,
}

#[derive(Debug, Clone)]
pub struct TrustFactor {
    pub category: TrustCategory,
    pub name: String,
    pub score_impact: f64,
    pub positive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustCategory {
    Identity,
    Device,
    Context,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRecommendation {
    Allow,
    AllowWithMfa,
    AllowWithSessionRecord,
    Deny,
}

impl TrustEvaluationEngine {
    pub fn new() -> Self {
        Self {
            identity_weight: 0.35,
            device_weight: 0.35,
            context_weight: 0.30,
            thresholds: TrustThresholds::default(),
        }
    }
    
    /// Evaluate trust for access request
    pub fn evaluate(
        &self,
        identity: &Identity,
        device: &Device,
        context: &AccessContext,
    ) -> TrustEvaluation {
        let mut factors = Vec::new();
        
        // Evaluate identity (0-100)
        let identity_score = self.evaluate_identity(identity, &mut factors);
        
        // Evaluate device (0-100)
        let device_score = self.evaluate_device(device, &mut factors);
        
        // Evaluate context (0-100)
        let context_score = self.evaluate_context(context, &mut factors);
        
        // Calculate weighted score
        let overall_score = 
            identity_score * self.identity_weight +
            device_score * self.device_weight +
            context_score * self.context_weight;
        
        // Determine trust level
        let trust_level = if overall_score >= 80.0 {
            TrustLevel::Full
        } else if overall_score >= 60.0 {
            TrustLevel::High
        } else if overall_score >= 40.0 {
            TrustLevel::Medium
        } else if overall_score >= 20.0 {
            TrustLevel::Low
        } else {
            TrustLevel::Untrusted
        };
        
        // Determine recommendation
        let recommendation = self.get_recommendation(overall_score);
        
        TrustEvaluation {
            overall_score,
            identity_score,
            device_score,
            context_score,
            trust_level,
            factors,
            recommendation,
        }
    }
    
    fn evaluate_identity(&self, identity: &Identity, factors: &mut Vec<TrustFactor>) -> f64 {
        let mut score = 50.0; // Base score
        
        // MFA verified
        if identity.mfa_verified {
            score += 25.0;
            factors.push(TrustFactor {
                category: TrustCategory::Identity,
                name: "MFA Verified".to_string(),
                score_impact: 25.0,
                positive: true,
            });
        } else {
            factors.push(TrustFactor {
                category: TrustCategory::Identity,
                name: "MFA Not Verified".to_string(),
                score_impact: -10.0,
                positive: false,
            });
        }
        
        // IdP verification
        match &identity.provider {
            crate::IdentityProvider::Local => {
                score += 10.0;
            }
            crate::IdentityProvider::Azure | crate::IdentityProvider::Okta => {
                score += 20.0;
                factors.push(TrustFactor {
                    category: TrustCategory::Identity,
                    name: "Enterprise IdP".to_string(),
                    score_impact: 20.0,
                    positive: true,
                });
            }
            _ => {
                score += 15.0;
            }
        }
        
        // Roles
        if !identity.roles.is_empty() {
            score += 5.0;
        }
        
        score.clamp(0.0, 100.0)
    }
    
    fn evaluate_device(&self, device: &Device, factors: &mut Vec<TrustFactor>) -> f64 {
        let mut score = 0.0;
        
        // Managed device
        if device.managed {
            score += 30.0;
            factors.push(TrustFactor {
                category: TrustCategory::Device,
                name: "Managed Device".to_string(),
                score_impact: 30.0,
                positive: true,
            });
        } else {
            factors.push(TrustFactor {
                category: TrustCategory::Device,
                name: "Unmanaged Device".to_string(),
                score_impact: -15.0,
                positive: false,
            });
        }
        
        // Compliant
        if device.compliant {
            score += 25.0;
            factors.push(TrustFactor {
                category: TrustCategory::Device,
                name: "Compliant".to_string(),
                score_impact: 25.0,
                positive: true,
            });
        }
        
        // Posture checks
        let posture = &device.posture;
        if posture.firewall_enabled {
            score += 10.0;
        }
        if posture.antivirus_running {
            score += 10.0;
        }
        if posture.disk_encrypted {
            score += 15.0;
        }
        if posture.os_patched {
            score += 10.0;
        }
        if posture.screen_lock_enabled {
            score += 5.0;
        }
        
        // Jailbroken penalty
        if posture.jailbroken {
            score -= 50.0;
            factors.push(TrustFactor {
                category: TrustCategory::Device,
                name: "Jailbroken Device".to_string(),
                score_impact: -50.0,
                positive: false,
            });
        }
        
        // Valid certificate
        let has_valid_cert = device.certificates.iter()
            .any(|c| chrono::Utc::now() < c.valid_until);
        if has_valid_cert {
            score += 15.0;
            factors.push(TrustFactor {
                category: TrustCategory::Device,
                name: "Valid Certificate".to_string(),
                score_impact: 15.0,
                positive: true,
            });
        }
        
        score.clamp(0.0, 100.0)
    }
    
    fn evaluate_context(&self, context: &AccessContext, factors: &mut Vec<TrustFactor>) -> f64 {
        let mut score = 70.0; // Base score
        
        // Network type
        match context.network_type {
            crate::NetworkType::Corporate => {
                score += 20.0;
                factors.push(TrustFactor {
                    category: TrustCategory::Context,
                    name: "Corporate Network".to_string(),
                    score_impact: 20.0,
                    positive: true,
                });
            }
            crate::NetworkType::VPN => {
                score += 15.0;
            }
            crate::NetworkType::Home => {
                score += 5.0;
            }
            crate::NetworkType::PublicWifi => {
                score -= 25.0;
                factors.push(TrustFactor {
                    category: TrustCategory::Context,
                    name: "Public WiFi".to_string(),
                    score_impact: -25.0,
                    positive: false,
                });
            }
            _ => {}
        }
        
        // Risk signals
        for signal in &context.signals {
            let impact = match signal.severity {
                crate::RiskSeverity::Low => -5.0,
                crate::RiskSeverity::Medium => -15.0,
                crate::RiskSeverity::High => -30.0,
                crate::RiskSeverity::Critical => -50.0,
            };
            score += impact;
            factors.push(TrustFactor {
                category: TrustCategory::Context,
                name: format!("{:?}", signal.signal_type),
                score_impact: impact,
                positive: false,
            });
        }
        
        // Time of day (working hours bonus)
        let hour = context.time_of_access.time().hour();
        if hour >= 8 && hour <= 18 {
            score += 5.0;
        }
        
        score.clamp(0.0, 100.0)
    }
    
    fn get_recommendation(&self, score: f64) -> TrustRecommendation {
        if score >= self.thresholds.allow {
            TrustRecommendation::Allow
        } else if score >= self.thresholds.allow_with_mfa {
            TrustRecommendation::AllowWithMfa
        } else if score >= self.thresholds.allow_with_session_record {
            TrustRecommendation::AllowWithSessionRecord
        } else {
            TrustRecommendation::Deny
        }
    }
}

impl Default for TrustEvaluationEngine {
    fn default() -> Self {
        Self::new()
    }
}

use chrono::Timelike;
