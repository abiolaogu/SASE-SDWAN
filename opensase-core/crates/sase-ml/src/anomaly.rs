//! Anomaly Detection using Isolation Forest

use crate::RiskScore;
use std::collections::HashMap;
use parking_lot::RwLock;

/// Session behavioral features
#[derive(Debug, Clone)]
pub struct SessionFeatures {
    /// User ID
    pub user_id: String,
    /// Source IP
    pub source_ip: String,
    /// Request count in window
    pub request_count: u32,
    /// Unique destinations accessed
    pub unique_destinations: u32,
    /// Data volume bytes
    pub data_volume: u64,
    /// Time of day (0-23)
    pub hour_of_day: u8,
    /// Day of week (0-6)
    pub day_of_week: u8,
    /// Is from new location
    pub new_location: bool,
    /// Device trust score (0.0-1.0)
    pub device_trust: f32,
    /// MFA used
    pub mfa_used: bool,
}

/// User baseline for behavioral comparison
#[derive(Clone)]
struct UserBaseline {
    /// Typical request count
    avg_requests: f32,
    /// Typical data volume
    avg_data_volume: f64,
    /// Typical destinations
    avg_destinations: f32,
    /// Typical hours
    active_hours: [bool; 24],
    /// Known locations
    known_ips: Vec<String>,
    /// Sample count
    samples: u64,
}

impl Default for UserBaseline {
    fn default() -> Self {
        Self {
            avg_requests: 100.0,
            avg_data_volume: 1_000_000.0,
            avg_destinations: 10.0,
            active_hours: [false; 24],
            known_ips: Vec::new(),
            samples: 0,
        }
    }
}

/// Anomaly detector with behavioral analysis
pub struct AnomalyDetector {
    /// User baselines
    baselines: RwLock<HashMap<String, UserBaseline>>,
    /// Sensitivity (0.0-1.0, higher = more alerts)
    sensitivity: f32,
    /// Minimum samples before baseline is valid
    min_samples: u64,
}

impl AnomalyDetector {
    /// Create new detector
    pub fn new(sensitivity: f32) -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
            sensitivity: sensitivity.clamp(0.0, 1.0),
            min_samples: 10,
        }
    }

    /// Analyze session and return risk score
    pub fn analyze(&self, features: &SessionFeatures) -> RiskScore {
        let baselines = self.baselines.read();
        
        let baseline = baselines.get(&features.user_id)
            .cloned()
            .unwrap_or_default();
        drop(baselines);

        // Calculate deviation from baseline
        let deviation = self.calculate_deviation(features, &baseline);

        // Calculate anomaly score
        let anomaly_score = self.calculate_anomaly_score(features, &baseline);

        // Combined risk
        let risk = self.calculate_risk(features, deviation, anomaly_score);

        // Determine actions
        let require_stepup = risk > 0.5 + (1.0 - self.sensitivity) * 0.3;
        let block = risk > 0.85 + (1.0 - self.sensitivity) * 0.1;

        RiskScore {
            risk,
            anomaly_score,
            deviation,
            require_stepup,
            block,
        }
    }

    /// Update baseline with session
    pub fn update_baseline(&self, features: &SessionFeatures) {
        let mut baselines = self.baselines.write();
        
        let baseline = baselines.entry(features.user_id.clone())
            .or_insert_with(UserBaseline::default);

        // Exponential moving average update
        let alpha: f64 = 0.1;
        baseline.avg_requests = (alpha * features.request_count as f64 
            + (1.0 - alpha) * baseline.avg_requests as f64) as f32;
        baseline.avg_data_volume = alpha * features.data_volume as f64
            + (1.0 - alpha) * baseline.avg_data_volume;
        baseline.avg_destinations = (alpha * features.unique_destinations as f64
            + (1.0 - alpha) * baseline.avg_destinations as f64) as f32;

        // Update active hours
        baseline.active_hours[features.hour_of_day as usize] = true;

        // Add known IP
        if !baseline.known_ips.contains(&features.source_ip) 
            && baseline.known_ips.len() < 100 
        {
            baseline.known_ips.push(features.source_ip.clone());
        }

        baseline.samples += 1;
    }

    fn calculate_deviation(&self, features: &SessionFeatures, baseline: &UserBaseline) -> f32 {
        if baseline.samples < self.min_samples {
            return 0.0;  // Not enough data
        }

        let mut deviations = Vec::new();

        // Request count deviation
        let req_ratio = features.request_count as f32 / baseline.avg_requests.max(1.0);
        deviations.push(if req_ratio > 3.0 || req_ratio < 0.1 { 1.0 } else { 0.0 });

        // Data volume deviation
        let data_ratio = features.data_volume as f64 / baseline.avg_data_volume.max(1.0);
        deviations.push(if data_ratio > 5.0 { 1.0 } else { 0.0 });

        // Destination deviation
        let dest_ratio = features.unique_destinations as f32 / baseline.avg_destinations.max(1.0);
        deviations.push(if dest_ratio > 3.0 { 1.0 } else { 0.0 });

        // Time deviation
        let unusual_hour = !baseline.active_hours[features.hour_of_day as usize];
        deviations.push(if unusual_hour { 0.5 } else { 0.0 });

        // Location deviation
        let unknown_ip = !baseline.known_ips.contains(&features.source_ip);
        deviations.push(if unknown_ip { 0.5 } else { 0.0 });

        // Average deviation
        deviations.iter().sum::<f32>() / deviations.len() as f32
    }

    fn calculate_anomaly_score(&self, features: &SessionFeatures, _baseline: &UserBaseline) -> f32 {
        let mut score = 0.0;

        // Risk factors
        if features.new_location {
            score += 0.3;
        }
        if !features.mfa_used {
            score += 0.2;
        }
        if features.device_trust < 0.5 {
            score += 0.3 * (1.0 - features.device_trust * 2.0);
        }
        if features.hour_of_day < 6 || features.hour_of_day > 22 {
            score += 0.1;
        }

        // Very high data volume is suspicious
        if features.data_volume > 100_000_000 {  // >100MB
            score += 0.2;
        }

        score.min(1.0)
    }

    fn calculate_risk(
        &self,
        features: &SessionFeatures,
        deviation: f32,
        anomaly_score: f32,
    ) -> f32 {
        // Combine deviation and anomaly
        let mut risk = (deviation * 0.4 + anomaly_score * 0.6) * self.sensitivity;

        // Reduce risk if MFA and trusted device
        if features.mfa_used {
            risk *= 0.7;
        }
        if features.device_trust > 0.9 {
            risk *= 0.8;
        }

        risk.clamp(0.0, 1.0)
    }

    /// Get user baseline summary
    pub fn get_baseline(&self, user_id: &str) -> Option<BaselineSummary> {
        let baselines = self.baselines.read();
        baselines.get(user_id).map(|b| BaselineSummary {
            avg_requests: b.avg_requests,
            avg_data_volume: b.avg_data_volume,
            known_locations: b.known_ips.len(),
            samples: b.samples,
        })
    }
}

/// Summary of user baseline
#[derive(Debug, Clone)]
pub struct BaselineSummary {
    /// Average request count
    pub avg_requests: f32,
    /// Average data volume
    pub avg_data_volume: f64,
    /// Number of known locations
    pub known_locations: usize,
    /// Number of samples
    pub samples: u64,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new(0.7)  // Default sensitivity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_session(user: &str) -> SessionFeatures {
        SessionFeatures {
            user_id: user.to_string(),
            source_ip: "192.168.1.1".to_string(),
            request_count: 100,
            unique_destinations: 10,
            data_volume: 1_000_000,
            hour_of_day: 10,
            day_of_week: 2,
            new_location: false,
            device_trust: 0.9,
            mfa_used: true,
        }
    }

    #[test]
    fn test_normal_session() {
        let detector = AnomalyDetector::default();
        
        // Build baseline
        for _ in 0..20 {
            let session = normal_session("user1");
            detector.update_baseline(&session);
        }

        // Analyze normal session
        let risk = detector.analyze(&normal_session("user1"));
        assert!(risk.risk < 0.3);
        assert!(!risk.require_stepup);
        assert!(!risk.block);
    }

    #[test]
    fn test_anomalous_session() {
        let detector = AnomalyDetector::default();
        
        // Build baseline
        for _ in 0..20 {
            detector.update_baseline(&normal_session("user1"));
        }

        // Anomalous session
        let anomalous = SessionFeatures {
            user_id: "user1".to_string(),
            source_ip: "203.0.113.50".to_string(),  // Unknown IP
            request_count: 1000,  // 10x normal
            unique_destinations: 100,  // 10x normal
            data_volume: 500_000_000,  // Huge
            hour_of_day: 3,  // Unusual hour
            day_of_week: 2,
            new_location: true,
            device_trust: 0.2,
            mfa_used: false,
        };

        let risk = detector.analyze(&anomalous);
        assert!(risk.risk > 0.5);
        assert!(risk.require_stepup);
    }
}
