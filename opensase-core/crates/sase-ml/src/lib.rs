//! ML Inference Engine for Predictive SASE Features
//!
//! # Features
//!
//! - AI Path Prediction: Predict congestion 100ms before occurrence
//! - Behavioral Analytics: Continuous identity verification
//! - Anomaly Detection: Isolation forest for threat detection
//! - Predictive DLP: NLP-based context understanding

#![warn(missing_docs)]

pub mod path_predictor;
pub mod anomaly;
pub mod features;

pub use path_predictor::PathPredictor;
pub use anomaly::AnomalyDetector;
pub use features::FeatureVector;

/// ML model configuration
#[derive(Debug, Clone)]
pub struct ModelConfig {
    /// Model path (ONNX file)
    pub model_path: Option<String>,
    /// Inference timeout in microseconds
    pub timeout_us: u64,
    /// Batch size for inference
    pub batch_size: usize,
    /// Input feature dimension
    pub input_dim: usize,
    /// Output dimension
    pub output_dim: usize,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model_path: None,
            timeout_us: 1000,  // 1ms max
            batch_size: 32,
            input_dim: 16,
            output_dim: 4,
        }
    }
}

/// Prediction result
#[derive(Debug, Clone)]
pub struct Prediction {
    /// Predicted class/path
    pub class: usize,
    /// Confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Probabilities for each class
    pub probabilities: Vec<f32>,
    /// Inference time in microseconds
    pub inference_time_us: u64,
}

/// Risk score from behavioral analysis
#[derive(Debug, Clone, Copy)]
pub struct RiskScore {
    /// Overall risk (0.0 - 1.0)
    pub risk: f32,
    /// Anomaly score
    pub anomaly_score: f32,
    /// Deviation from baseline
    pub deviation: f32,
    /// Whether to require step-up auth
    pub require_stepup: bool,
    /// Whether to block session
    pub block: bool,
}

impl RiskScore {
    /// Low risk score
    pub const fn low() -> Self {
        Self {
            risk: 0.1,
            anomaly_score: 0.0,
            deviation: 0.0,
            require_stepup: false,
            block: false,
        }
    }

    /// High risk score
    pub const fn high() -> Self {
        Self {
            risk: 0.9,
            anomaly_score: 1.0,
            deviation: 1.0,
            require_stepup: true,
            block: false,
        }
    }

    /// Critical risk score (block)
    pub const fn critical() -> Self {
        Self {
            risk: 1.0,
            anomaly_score: 1.0,
            deviation: 1.0,
            require_stepup: true,
            block: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_scores() {
        let low = RiskScore::low();
        assert!(!low.require_stepup);
        assert!(!low.block);

        let high = RiskScore::high();
        assert!(high.require_stepup);
        assert!(!high.block);

        let critical = RiskScore::critical();
        assert!(critical.block);
    }
}
