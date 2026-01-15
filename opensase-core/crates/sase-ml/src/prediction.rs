//! Threat Prediction Module
//!
//! Predictive analytics for SASE threat intelligence.
//! Adapted from BAC-BOS-AI patterns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Threat prediction result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub threat_type: PredictedThreat,
    pub probability: f64,
    pub time_horizon: TimeHorizon,
    pub confidence: f64,
    pub contributing_factors: Vec<ThreatFactor>,
    pub recommended_actions: Vec<RecommendedAction>,
    pub predicted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PredictedThreat {
    RansomwareAttack,
    DataBreach,
    DdosAttack,
    PhishingCampaign,
    InsiderThreat,
    SupplyChainCompromise,
    ZeroDayExploit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TimeHorizon {
    Hours24,
    Days7,
    Days30,
    Days90,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatFactor {
    pub factor: String,
    pub weight: f64,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action: String,
    pub priority: ActionPriority,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ActionPriority { Immediate, High, Medium, Low }

/// Threat predictor using intelligence feeds
pub struct ThreatPredictor {
    threat_intel_feeds: Vec<String>,
    historical_incidents: Vec<HistoricalIncident>,
}

#[derive(Clone, Debug)]
struct HistoricalIncident {
    threat_type: PredictedThreat,
    timestamp: DateTime<Utc>,
    indicators: Vec<String>,
}

impl ThreatPredictor {
    pub fn new() -> Self {
        Self {
            threat_intel_feeds: vec![],
            historical_incidents: vec![],
        }
    }
    
    /// Predict potential threats based on current indicators
    pub fn predict_threats(&self, indicators: &[String]) -> Vec<ThreatPrediction> {
        let mut predictions = Vec::new();
        
        // Analyze indicators for ransomware patterns
        if self.has_ransomware_indicators(indicators) {
            predictions.push(ThreatPrediction {
                threat_type: PredictedThreat::RansomwareAttack,
                probability: 0.75,
                time_horizon: TimeHorizon::Hours24,
                confidence: 0.8,
                contributing_factors: vec![
                    ThreatFactor {
                        factor: "suspicious_encryption".into(),
                        weight: 0.6,
                        description: "Unusual encryption activity detected".into(),
                    },
                ],
                recommended_actions: vec![
                    RecommendedAction {
                        action: "isolate_endpoints".into(),
                        priority: ActionPriority::Immediate,
                        description: "Isolate potentially compromised endpoints".into(),
                    },
                ],
                predicted_at: Utc::now(),
            });
        }
        
        predictions
    }
    
    fn has_ransomware_indicators(&self, indicators: &[String]) -> bool {
        indicators.iter().any(|i| {
            i.contains("encrypt") || i.contains("ransom") || i.contains("bitcoin")
        })
    }
}

impl Default for ThreatPredictor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threat_prediction() {
        let predictor = ThreatPredictor::new();
        let indicators = vec!["suspicious encryption activity".to_string()];
        let predictions = predictor.predict_threats(&indicators);
        
        assert!(!predictions.is_empty());
        assert!(predictions[0].probability > 0.5);
    }
}
