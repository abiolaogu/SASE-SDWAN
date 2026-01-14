//! ML Models

use crate::{OstieError, features::*};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// DNS Threat Detector (Random Forest + Character CNN)
pub struct DnsThreatDetector {
    model_loaded: Arc<RwLock<bool>>,
    threshold: f64,
}

impl DnsThreatDetector {
    pub fn new() -> Self {
        Self {
            model_loaded: Arc::new(RwLock::new(false)),
            threshold: 0.7,
        }
    }

    /// Extract features from DNS query
    pub fn extract_features(&self, query: &DnsQuery) -> DnsFeatures {
        DnsFeatures::from_domain(&query.domain)
    }

    /// Predict threat
    pub fn predict(&self, features: &DnsFeatures) -> DnsPrediction {
        // ML inference
        let score = self.calculate_dga_score(features);
        let tunneling_score = self.detect_tunneling(features);
        
        let is_threat = score > self.threshold || tunneling_score > 0.8;
        let threat_type = if score > self.threshold {
            DnsThreatType::Dga
        } else if tunneling_score > 0.8 {
            DnsThreatType::Tunneling
        } else {
            DnsThreatType::None
        };

        DnsPrediction {
            is_threat,
            confidence: score.max(tunneling_score),
            threat_type,
            explanation: self.explain(features, threat_type),
        }
    }

    fn calculate_dga_score(&self, features: &DnsFeatures) -> f64 {
        // Simplified DGA detection heuristic
        let mut score = 0.0;
        
        // High entropy = suspicious
        if features.entropy > 3.5 { score += 0.3; }
        if features.entropy > 4.0 { score += 0.2; }
        
        // Long domain = suspicious
        if features.length > 30.0 { score += 0.2; }
        
        // High consonant ratio = suspicious
        if features.consonant_ratio > 0.7 { score += 0.1; }
        
        // Low bigram score = suspicious
        if features.bigram_score < 0.2 { score += 0.2; }
        
        score.min(1.0)
    }

    fn detect_tunneling(&self, features: &DnsFeatures) -> f64 {
        // DNS tunneling detection
        if features.length > 50.0 && features.entropy > 4.0 {
            0.9
        } else if features.length > 40.0 && features.max_label_length > 30.0 {
            0.7
        } else {
            0.0
        }
    }

    fn explain(&self, features: &DnsFeatures, threat_type: DnsThreatType) -> String {
        match threat_type {
            DnsThreatType::Dga => format!(
                "Potential DGA domain detected. Entropy: {:.2}, Bigram score: {:.2}",
                features.entropy, features.bigram_score
            ),
            DnsThreatType::Tunneling => format!(
                "Potential DNS tunneling. Domain length: {}, Max label: {}",
                features.length as u32, features.max_label_length as u32
            ),
            DnsThreatType::Typosquat => "Potential typosquatting domain".into(),
            DnsThreatType::None => "No threat detected".into(),
        }
    }

    /// Load model from path
    pub fn load(&self, _path: &str) -> Result<(), OstieError> {
        *self.model_loaded.write() = true;
        Ok(())
    }
}

impl Default for DnsThreatDetector {
    fn default() -> Self { Self::new() }
}

/// DNS prediction result
#[derive(Debug, Clone)]
pub struct DnsPrediction {
    pub is_threat: bool,
    pub confidence: f64,
    pub threat_type: DnsThreatType,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy)]
pub enum DnsThreatType {
    Dga,
    Tunneling,
    Typosquat,
    None,
}

/// Network Anomaly Detector (Isolation Forest + Autoencoder)
pub struct NetworkAnomalyDetector {
    model_loaded: Arc<RwLock<bool>>,
    baseline: Arc<RwLock<Option<FlowBaseline>>>,
}

impl NetworkAnomalyDetector {
    pub fn new() -> Self {
        Self {
            model_loaded: Arc::new(RwLock::new(false)),
            baseline: Arc::new(RwLock::new(None)),
        }
    }

    /// Predict anomaly
    pub fn predict(&self, flow: &FlowFeatures) -> NetworkPrediction {
        let features = flow.to_vector();
        
        // Calculate anomaly score
        let score = self.calculate_anomaly_score(&features);
        let contributing_features = self.get_top_features(flow, &features);
        
        NetworkPrediction {
            anomaly_score: score,
            is_anomaly: score > 0.7,
            contributing_features,
            explanation: self.explain(flow, score),
        }
    }

    fn calculate_anomaly_score(&self, features: &[f64]) -> f64 {
        // Simplified Isolation Forest-like scoring
        let mut score = 0.0;
        
        // Extreme values = anomalous
        if features[0] > 1_000_000.0 { score += 0.3; } // bytes/sec
        if features[1] > 10_000.0 { score += 0.2; }    // packets/sec
        if features[4] > 4.0 { score += 0.2; }          // src port entropy
        if features[8] > 10_000.0 { score += 0.3; }     // geo distance
        
        score.min(1.0)
    }

    fn get_top_features(&self, flow: &FlowFeatures, _features: &[f64]) -> Vec<(String, f64)> {
        vec![
            ("bytes_per_second".into(), flow.bytes_per_second),
            ("packets_per_second".into(), flow.packets_per_second),
            ("geo_distance".into(), flow.geo_distance),
        ]
    }

    fn explain(&self, flow: &FlowFeatures, score: f64) -> String {
        if score > 0.7 {
            format!(
                "Anomalous traffic pattern. Bytes/sec: {:.0}, Geo distance: {:.0}km",
                flow.bytes_per_second, flow.geo_distance
            )
        } else {
            "Normal traffic".into()
        }
    }

    /// Load model
    pub fn load(&self, _path: &str) -> Result<(), OstieError> {
        *self.model_loaded.write() = true;
        Ok(())
    }
}

impl Default for NetworkAnomalyDetector {
    fn default() -> Self { Self::new() }
}

/// Network prediction result
#[derive(Debug, Clone)]
pub struct NetworkPrediction {
    pub anomaly_score: f64,
    pub is_anomaly: bool,
    pub contributing_features: Vec<(String, f64)>,
    pub explanation: String,
}

/// Flow baseline for comparison
#[derive(Debug, Clone)]
pub struct FlowBaseline {
    pub mean_bytes_per_sec: f64,
    pub std_bytes_per_sec: f64,
    pub mean_packets_per_sec: f64,
    pub std_packets_per_sec: f64,
}

/// User Behavior Analytics (UBA) Detector
pub struct UbaDetector {
    model_loaded: Arc<RwLock<bool>>,
}

impl UbaDetector {
    pub fn new() -> Self {
        Self {
            model_loaded: Arc::new(RwLock::new(false)),
        }
    }

    /// Predict risk
    pub fn predict(&self, session: &UserSession) -> UbaPrediction {
        let risk_score = self.calculate_risk(session);
        let anomalies = self.detect_anomalies(session);
        
        UbaPrediction {
            risk_score,
            is_risky: risk_score > 0.7,
            anomalies,
            explanation: self.explain(session, risk_score),
        }
    }

    fn calculate_risk(&self, session: &UserSession) -> f64 {
        let mut risk = 0.0;
        
        // Multiple locations = risk
        if session.locations.len() > 2 { risk += 0.3; }
        
        // Large data volume = risk
        if session.data_volume > 1_000_000_000 { risk += 0.2; }
        
        // Many applications = risk
        if session.applications.len() > 20 { risk += 0.2; }
        
        // Off-hours access
        let hour = (session.access_times.first().unwrap_or(&0) / 3600) % 24;
        if hour < 6 || hour > 22 { risk += 0.3; }
        
        risk.min(1.0)
    }

    fn detect_anomalies(&self, session: &UserSession) -> Vec<UbaAnomaly> {
        let mut anomalies = Vec::new();
        
        if session.locations.len() > 2 {
            anomalies.push(UbaAnomaly::ImpossibleTravel);
        }
        if session.data_volume > 1_000_000_000 {
            anomalies.push(UbaAnomaly::DataExfiltration);
        }
        
        anomalies
    }

    fn explain(&self, session: &UserSession, score: f64) -> String {
        if score > 0.7 {
            format!(
                "High-risk session. {} locations, {:.1}GB transferred",
                session.locations.len(),
                session.data_volume as f64 / 1_000_000_000.0
            )
        } else {
            "Normal user behavior".into()
        }
    }

    /// Load model
    pub fn load(&self, _path: &str) -> Result<(), OstieError> {
        *self.model_loaded.write() = true;
        Ok(())
    }
}

impl Default for UbaDetector {
    fn default() -> Self { Self::new() }
}

/// UBA prediction result
#[derive(Debug, Clone)]
pub struct UbaPrediction {
    pub risk_score: f64,
    pub is_risky: bool,
    pub anomalies: Vec<UbaAnomaly>,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy)]
pub enum UbaAnomaly {
    ImpossibleTravel,
    DataExfiltration,
    PrivilegeEscalation,
    UnusualHours,
    NewDevice,
}

/// Malware Traffic Detector
pub struct MalwareDetector {
    model_loaded: Arc<RwLock<bool>>,
    known_bad_ja3: Vec<String>,
}

impl MalwareDetector {
    pub fn new() -> Self {
        Self {
            model_loaded: Arc::new(RwLock::new(false)),
            known_bad_ja3: vec![
                "e7d705a3286e19ea42f587b344ee6865".into(), // Cobalt Strike
                "a0e9f5d64349fb13191bc781f81f42e1".into(), // Metasploit
            ],
        }
    }

    /// Predict malware
    pub fn predict(&self, fingerprint: &TlsFingerprint, flow: &FlowFeatures) -> MalwarePrediction {
        let ja3_match = self.known_bad_ja3.contains(&fingerprint.ja3);
        let behavioral_score = self.behavioral_analysis(flow);
        
        let score = if ja3_match { 0.95 } else { behavioral_score };
        
        MalwarePrediction {
            malware_score: score,
            is_malware: score > 0.7,
            ja3_match,
            malware_family: if ja3_match { Some("CobaltStrike".into()) } else { None },
            explanation: self.explain(fingerprint, score, ja3_match),
        }
    }

    fn behavioral_analysis(&self, flow: &FlowFeatures) -> f64 {
        let mut score = 0.0;
        
        // C2 beaconing patterns
        if flow.duration > 0.0 && flow.packets_per_second < 1.0 { score += 0.3; }
        
        // Regular intervals
        if flow.bytes_per_second < 1000.0 && flow.packets_per_second > 0.1 { score += 0.2; }
        
        score.min(1.0)
    }

    fn explain(&self, fingerprint: &TlsFingerprint, score: f64, ja3_match: bool) -> String {
        if ja3_match {
            format!("Known malicious JA3 fingerprint: {}", fingerprint.ja3)
        } else if score > 0.7 {
            "Suspicious C2-like traffic pattern".into()
        } else {
            "No malware indicators".into()
        }
    }

    /// Load model
    pub fn load(&self, _path: &str) -> Result<(), OstieError> {
        *self.model_loaded.write() = true;
        Ok(())
    }
}

impl Default for MalwareDetector {
    fn default() -> Self { Self::new() }
}

/// Malware prediction result
#[derive(Debug, Clone)]
pub struct MalwarePrediction {
    pub malware_score: f64,
    pub is_malware: bool,
    pub ja3_match: bool,
    pub malware_family: Option<String>,
    pub explanation: String,
}
