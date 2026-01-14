//! Feedback Loop for Model Retraining

use crate::alerts::{AnalystFeedback, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Feedback manager
pub struct FeedbackManager {
    /// Collected feedback
    feedback: Arc<RwLock<Vec<FeedbackRecord>>>,
    /// Model performance metrics
    metrics: Arc<RwLock<ModelMetrics>>,
}

impl FeedbackManager {
    pub fn new() -> Self {
        Self {
            feedback: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(ModelMetrics::default())),
        }
    }

    /// Record feedback
    pub fn record(&self, alert_id: &str, model: &str, feedback: &AnalystFeedback) {
        let record = FeedbackRecord {
            alert_id: alert_id.to_string(),
            model: model.to_string(),
            verdict: feedback.verdict,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        self.feedback.write().push(record);
        self.update_metrics(model, &feedback.verdict);
    }

    /// Get feedback for model retraining
    pub fn get_feedback_for_training(&self, model: &str) -> Vec<FeedbackRecord> {
        self.feedback.read()
            .iter()
            .filter(|f| f.model == model)
            .cloned()
            .collect()
    }

    /// Get model performance metrics
    pub fn get_metrics(&self, model: &str) -> Option<ModelPerformance> {
        self.metrics.read().models.get(model).cloned()
    }

    /// Check for model drift
    pub fn check_drift(&self, model: &str) -> DriftStatus {
        let metrics = self.metrics.read();
        if let Some(perf) = metrics.models.get(model) {
            if perf.false_positive_rate > 0.2 {
                DriftStatus::HighFalsePositives
            } else if perf.precision < 0.7 {
                DriftStatus::LowPrecision
            } else {
                DriftStatus::Healthy
            }
        } else {
            DriftStatus::Unknown
        }
    }

    fn update_metrics(&self, model: &str, verdict: &Verdict) {
        let mut metrics = self.metrics.write();
        let perf = metrics.models
            .entry(model.to_string())
            .or_insert(ModelPerformance::default());

        match verdict {
            Verdict::TruePositive => perf.true_positives += 1,
            Verdict::FalsePositive => perf.false_positives += 1,
            Verdict::NeedsReview => {}
        }

        perf.update_rates();
    }
}

impl Default for FeedbackManager {
    fn default() -> Self { Self::new() }
}

/// Feedback record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    pub alert_id: String,
    pub model: String,
    pub verdict: Verdict,
    pub timestamp: u64,
}

/// Model metrics
#[derive(Debug, Clone, Default)]
pub struct ModelMetrics {
    pub models: HashMap<String, ModelPerformance>,
}

/// Performance for a single model
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelPerformance {
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub false_positive_rate: f64,
}

impl ModelPerformance {
    fn update_rates(&mut self) {
        let total = self.true_positives + self.false_positives;
        if total > 0 {
            self.precision = self.true_positives as f64 / total as f64;
            self.false_positive_rate = self.false_positives as f64 / total as f64;
        }
        
        let actual_positive = self.true_positives + self.false_negatives;
        if actual_positive > 0 {
            self.recall = self.true_positives as f64 / actual_positive as f64;
        }
        
        if self.precision + self.recall > 0.0 {
            self.f1_score = 2.0 * self.precision * self.recall / (self.precision + self.recall);
        }
    }
}

/// Drift status
#[derive(Debug, Clone, Copy)]
pub enum DriftStatus {
    Healthy,
    HighFalsePositives,
    LowPrecision,
    NeedsRetraining,
    Unknown,
}

/// Retraining request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrainingRequest {
    pub model: String,
    pub reason: String,
    pub include_feedback: bool,
    pub priority: RetrainingPriority,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RetrainingPriority {
    Immediate,
    Scheduled,
    Background,
}
