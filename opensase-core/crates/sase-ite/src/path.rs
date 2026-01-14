//! Optimal Path Selection

use crate::telemetry::{PathMetrics, TelemetryCollector, CongestionLevel};
use crate::classifier::AppCategory;
use std::collections::HashMap;
use std::sync::Arc;

/// Path selector
pub struct PathSelector {
    telemetry: Arc<TelemetryCollector>,
    paths: HashMap<String, Vec<PathInfo>>,  // destination → available paths
}

impl PathSelector {
    /// Create new selector
    pub fn new(telemetry: Arc<TelemetryCollector>) -> Self {
        Self {
            telemetry,
            paths: HashMap::new(),
        }
    }

    /// Register available path
    pub fn add_path(&mut self, destination: &str, path: PathInfo) {
        self.paths.entry(destination.to_string())
            .or_default()
            .push(path);
    }

    /// Select best path for flow
    pub fn select(&self, destination: &str, category: AppCategory) -> Option<PathSelection> {
        let paths = self.paths.get(destination)?;
        if paths.is_empty() { return None; }

        let scored: Vec<_> = paths.iter()
            .filter_map(|p| {
                let metrics = self.telemetry.get(&p.path_id)?;
                let score = self.score_path(&metrics, category, p);
                Some((p, metrics, score))
            })
            .collect();

        if scored.is_empty() {
            // Return first path even without metrics
            return Some(PathSelection {
                path_id: paths[0].path_id.clone(),
                score: PathScore::default(),
                reason: "No metrics available".into(),
            });
        }

        // Find best
        let (best_path, metrics, score) = scored.iter()
            .max_by(|a, b| a.2.total.partial_cmp(&b.2.total).unwrap())?;

        Some(PathSelection {
            path_id: best_path.path_id.clone(),
            score: score.clone(),
            reason: self.explain_selection(&score, category),
        })
    }

    /// Score path for application category
    fn score_path(&self, metrics: &PathMetrics, category: AppCategory, path: &PathInfo) -> PathScore {
        let latency_sla = category.latency_sla() as f64;
        let latency_actual = metrics.latency_p50.as_millis() as f64;
        
        // Latency score (0-100)
        let latency_score = if latency_actual <= latency_sla {
            100.0
        } else {
            (100.0 * latency_sla / latency_actual).max(0.0)
        };

        // Jitter score (important for voice/video)
        let jitter_score = 100.0 - (metrics.jitter.as_millis() as f64).min(100.0);

        // Loss score
        let loss_score = 100.0 * (1.0 - metrics.loss_rate);

        // Bandwidth score
        let bandwidth_score = if metrics.bandwidth_available > 100_000_000 {
            100.0
        } else {
            (metrics.bandwidth_available as f64 / 100_000_000.0) * 100.0
        };

        // Cost score (prefer cheaper paths)
        let cost_score = 100.0 - (path.cost_factor * 100.0);

        // Apply weights based on category
        let (w_lat, w_jit, w_loss, w_bw, w_cost) = match category {
            AppCategory::VoiceVideo => (0.50, 0.30, 0.20, 0.00, 0.00),  // Voice: latency+jitter critical
            AppCategory::Interactive => (0.35, 0.15, 0.20, 0.15, 0.15),
            AppCategory::Bulk => (0.10, 0.00, 0.30, 0.00, 0.60),        // Bulk: cost-optimized
            AppCategory::Background => (0.10, 0.05, 0.10, 0.25, 0.50),
        };

        let total = latency_score * w_lat
            + jitter_score * w_jit
            + loss_score * w_loss
            + bandwidth_score * w_bw
            + cost_score * w_cost;

        PathScore {
            latency: latency_score,
            jitter: jitter_score,
            loss: loss_score,
            bandwidth: bandwidth_score,
            cost: cost_score,
            total,
        }
    }

    fn explain_selection(&self, score: &PathScore, category: AppCategory) -> String {
        match category {
            AppCategory::VoiceVideo => {
                format!("Optimized for voice/video (latency: {:.0}, jitter: {:.0})", 
                    score.latency, score.jitter)
            }
            AppCategory::Interactive => {
                format!("Balanced for interactive (latency: {:.0}, loss: {:.0})",
                    score.latency, score.loss)
            }
            AppCategory::Bulk => {
                format!("Optimized for throughput (bandwidth: {:.0})", score.bandwidth)
            }
            AppCategory::Background => {
                format!("Cost-optimized (cost: {:.0})", score.cost)
            }
        }
    }

    /// Get multiple paths for ECMP
    pub fn select_ecmp(&self, destination: &str, category: AppCategory, count: usize) -> Vec<PathSelection> {
        let paths = match self.paths.get(destination) {
            Some(p) => p,
            None => return vec![],
        };

        let mut scored: Vec<_> = paths.iter()
            .filter_map(|p| {
                let metrics = self.telemetry.get(&p.path_id)?;
                let score = self.score_path(&metrics, category, p);
                Some((p.clone(), score))
            })
            .collect();

        // Sort by total score
        scored.sort_by(|a, b| b.1.total.partial_cmp(&a.1.total).unwrap());

        // Return top N
        scored.into_iter()
            .take(count)
            .map(|(p, s)| PathSelection {
                path_id: p.path_id,
                score: s.clone(),
                reason: format!("ECMP path (score: {:.0})", s.total),
            })
            .collect()
    }

    /// Check if path switch is needed
    pub fn should_switch(&self, current: &str, destination: &str, category: AppCategory) -> Option<PathSelection> {
        let current_metrics = self.telemetry.get(current)?;
        let congestion = self.telemetry.detect_congestion(current);
        
        // Trigger switch if:
        // 1. Current path is congested
        // 2. Current path quality dropped significantly
        // 3. A significantly better path is available

        let should_switch = match congestion {
            CongestionLevel::Severe => true,
            CongestionLevel::Moderate if current_metrics.loss_rate > 0.02 => true,
            _ => false,
        };

        if !should_switch {
            return None;
        }

        // Find better path
        let best = self.select(destination, category)?;
        if best.path_id != current && best.score.total > current_metrics.quality_score() + 10.0 {
            Some(best)
        } else {
            None
        }
    }
}

/// Path information
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path_id: String,
    pub via_pop: String,
    pub hops: Vec<String>,
    pub cost_factor: f64,  // 0.0 = free, 1.0 = most expensive
}

/// Path score
#[derive(Debug, Clone, Default)]
pub struct PathScore {
    pub latency: f64,
    pub jitter: f64,
    pub loss: f64,
    pub bandwidth: f64,
    pub cost: f64,
    pub total: f64,
}

/// Path selection result
#[derive(Debug, Clone)]
pub struct PathSelection {
    pub path_id: String,
    pub score: PathScore,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_path_scoring() {
        let telemetry = Arc::new(TelemetryCollector::default());
        let mut selector = PathSelector::new(telemetry.clone());
        
        // Add paths
        selector.add_path("app.example.com", PathInfo {
            path_id: "direct".into(),
            via_pop: "us-east".into(),
            hops: vec!["us-east".into()],
            cost_factor: 0.5,
        });
        
        selector.add_path("app.example.com", PathInfo {
            path_id: "via-eu".into(),
            via_pop: "eu-west".into(),
            hops: vec!["us-east".into(), "eu-west".into()],
            cost_factor: 0.8,
        });
        
        // Record metrics
        telemetry.record(PathMetrics {
            path_id: "direct".into(),
            latency_p50: Duration::from_millis(20),
            latency_p99: Duration::from_millis(40),
            jitter: Duration::from_millis(2),
            loss_rate: 0.001,
            bandwidth_available: 1_000_000_000,
            congestion_score: 0.1,
            timestamp: 0,
        });
        
        let selection = selector.select("app.example.com", AppCategory::VoiceVideo).unwrap();
        assert_eq!(selection.path_id, "direct");
    }
}
