//! Risk Scoring Engine
//!
//! Real-time risk evaluation for access decisions.

use crate::{AccessRequest, RiskSignal, RiskSignalType, RiskSeverity};

/// Risk evaluation engine
pub struct RiskEngine {
    /// Signal weights
    signal_weights: std::collections::HashMap<RiskSignalType, f64>,
    /// Baseline risk per network type
    network_risk: std::collections::HashMap<crate::NetworkType, f64>,
    /// Historical risk data
    user_risk_history: dashmap::DashMap<String, UserRiskProfile>,
}

#[derive(Clone)]
struct UserRiskProfile {
    baseline_risk: f64,
    recent_signals: Vec<RiskSignal>,
    anomaly_count: u32,
    last_updated: chrono::DateTime<chrono::Utc>,
}

impl RiskEngine {
    pub fn new() -> Self {
        let mut signal_weights = std::collections::HashMap::new();
        signal_weights.insert(RiskSignalType::ImpossibleTravel, 40.0);
        signal_weights.insert(RiskSignalType::NewDevice, 15.0);
        signal_weights.insert(RiskSignalType::NewLocation, 10.0);
        signal_weights.insert(RiskSignalType::UnusualTime, 5.0);
        signal_weights.insert(RiskSignalType::UnusualBehavior, 20.0);
        signal_weights.insert(RiskSignalType::CompromisedCredential, 80.0);
        signal_weights.insert(RiskSignalType::MalwareDetected, 90.0);
        signal_weights.insert(RiskSignalType::PrivilegeEscalation, 60.0);
        signal_weights.insert(RiskSignalType::DataExfiltration, 70.0);
        signal_weights.insert(RiskSignalType::BruteForceAttempt, 50.0);
        
        let mut network_risk = std::collections::HashMap::new();
        network_risk.insert(crate::NetworkType::Corporate, 0.0);
        network_risk.insert(crate::NetworkType::VPN, 5.0);
        network_risk.insert(crate::NetworkType::Home, 10.0);
        network_risk.insert(crate::NetworkType::Mobile, 15.0);
        network_risk.insert(crate::NetworkType::PublicWifi, 30.0);
        network_risk.insert(crate::NetworkType::Unknown, 25.0);
        
        Self {
            signal_weights,
            network_risk,
            user_risk_history: dashmap::DashMap::new(),
        }
    }
    
    /// Evaluate risk for access request
    pub async fn evaluate(&self, request: &AccessRequest) -> f64 {
        let mut risk_score = 0.0;
        
        // Base risk from network type
        risk_score += self.network_risk
            .get(&request.context.network_type)
            .copied()
            .unwrap_or(20.0);
        
        // Device trust factor
        risk_score += self.device_risk(&request.device);
        
        // Signal-based risk
        for signal in &request.context.signals {
            risk_score += self.signal_weights
                .get(&signal.signal_type)
                .copied()
                .unwrap_or(10.0);
            
            // Severity multiplier
            let multiplier = match signal.severity {
                RiskSeverity::Low => 0.5,
                RiskSeverity::Medium => 1.0,
                RiskSeverity::High => 1.5,
                RiskSeverity::Critical => 2.0,
            };
            risk_score += risk_score * (multiplier - 1.0);
        }
        
        // Resource sensitivity factor
        risk_score += self.resource_risk(&request.resource);
        
        // Historical user risk
        if let Some(profile) = self.user_risk_history.get(&request.identity.user_id) {
            risk_score += profile.baseline_risk * 0.2;
        }
        
        // Update user risk profile
        self.update_user_profile(&request.identity.user_id, &request.context.signals);
        
        // Cap at 100
        risk_score.min(100.0)
    }
    
    fn device_risk(&self, device: &crate::Device) -> f64 {
        let mut risk = 0.0;
        
        // Trust level
        risk += match device.trust_level {
            crate::TrustLevel::Untrusted => 30.0,
            crate::TrustLevel::Low => 20.0,
            crate::TrustLevel::Medium => 10.0,
            crate::TrustLevel::High => 5.0,
            crate::TrustLevel::Full => 0.0,
        };
        
        // Managed/compliant
        if !device.managed {
            risk += 10.0;
        }
        if !device.compliant {
            risk += 15.0;
        }
        
        // Jailbroken
        if device.posture.jailbroken {
            risk += 40.0;
        }
        
        risk
    }
    
    fn resource_risk(&self, resource: &crate::Resource) -> f64 {
        match resource.sensitivity {
            crate::DataSensitivity::Public => 0.0,
            crate::DataSensitivity::Internal => 5.0,
            crate::DataSensitivity::Confidential => 10.0,
            crate::DataSensitivity::Restricted => 15.0,
            crate::DataSensitivity::TopSecret => 25.0,
        }
    }
    
    fn update_user_profile(&self, user_id: &str, signals: &[RiskSignal]) {
        let now = chrono::Utc::now();
        
        self.user_risk_history.entry(user_id.to_string())
            .and_modify(|profile| {
                profile.recent_signals.extend(signals.iter().cloned());
                profile.anomaly_count += signals.len() as u32;
                profile.last_updated = now;
                
                // Recalculate baseline
                if profile.anomaly_count > 10 {
                    profile.baseline_risk = (profile.baseline_risk + 5.0).min(50.0);
                }
            })
            .or_insert(UserRiskProfile {
                baseline_risk: 0.0,
                recent_signals: signals.to_vec(),
                anomaly_count: signals.len() as u32,
                last_updated: now,
            });
    }
    
    /// Get user risk score
    pub fn get_user_risk(&self, user_id: &str) -> f64 {
        self.user_risk_history.get(user_id)
            .map(|p| p.baseline_risk)
            .unwrap_or(0.0)
    }
    
    /// Report security incident
    pub fn report_incident(&self, user_id: &str, signal: RiskSignal) {
        self.user_risk_history.entry(user_id.to_string())
            .and_modify(|profile| {
                profile.recent_signals.push(signal.clone());
                profile.anomaly_count += 1;
                profile.baseline_risk = (profile.baseline_risk + 20.0).min(100.0);
            })
            .or_insert(UserRiskProfile {
                baseline_risk: 20.0,
                recent_signals: vec![signal],
                anomaly_count: 1,
                last_updated: chrono::Utc::now(),
            });
    }
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new()
    }
}
