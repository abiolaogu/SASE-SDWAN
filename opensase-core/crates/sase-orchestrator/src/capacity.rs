//! Capacity Planning and Auto-Scaling

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Capacity planner
pub struct CapacityPlanner {
    /// Historical metrics per PoP
    metrics: HashMap<String, Vec<MetricSample>>,
    /// Scaling rules
    rules: Vec<ScalingRule>,
    /// Alerts
    alerts: Vec<CapacityAlert>,
}

impl CapacityPlanner {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            rules: Self::default_rules(),
            alerts: Vec::new(),
        }
    }

    fn default_rules() -> Vec<ScalingRule> {
        vec![
            ScalingRule {
                name: "high_cpu".into(),
                metric: MetricType::CpuUtilization,
                threshold: 70.0,
                action: ScalingAction::ScaleUp,
                cooldown_secs: 300,
            },
            ScalingRule {
                name: "low_cpu".into(),
                metric: MetricType::CpuUtilization,
                threshold: 20.0,
                action: ScalingAction::ScaleDown,
                cooldown_secs: 600,
            },
            ScalingRule {
                name: "high_bandwidth".into(),
                metric: MetricType::BandwidthUtilization,
                threshold: 80.0,
                action: ScalingAction::ScaleUp,
                cooldown_secs: 300,
            },
            ScalingRule {
                name: "high_latency".into(),
                metric: MetricType::Latency,
                threshold: 50.0,  // ms
                action: ScalingAction::AddPop,
                cooldown_secs: 3600,
            },
        ]
    }

    /// Record metric sample
    pub fn record_metric(&mut self, pop_id: &str, metric: MetricType, value: f64) {
        let sample = MetricSample {
            metric,
            value,
            timestamp: now(),
        };
        
        self.metrics.entry(pop_id.to_string())
            .or_default()
            .push(sample);
        
        // Prune old samples (keep last hour)
        let cutoff = now() - 3600;
        if let Some(samples) = self.metrics.get_mut(pop_id) {
            samples.retain(|s| s.timestamp > cutoff);
        }
    }

    /// Check scaling rules
    pub fn evaluate(&self, pop_id: &str) -> Vec<ScalingDecision> {
        let mut decisions = Vec::new();
        
        let samples = match self.metrics.get(pop_id) {
            Some(s) => s,
            None => return decisions,
        };

        for rule in &self.rules {
            let matching: Vec<_> = samples.iter()
                .filter(|s| s.metric == rule.metric)
                .collect();
            
            if matching.is_empty() { continue; }
            
            let avg = matching.iter().map(|s| s.value).sum::<f64>() / matching.len() as f64;
            
            let triggered = match rule.action {
                ScalingAction::ScaleUp | ScalingAction::AddPop => avg > rule.threshold,
                ScalingAction::ScaleDown => avg < rule.threshold,
            };
            
            if triggered {
                decisions.push(ScalingDecision {
                    pop_id: pop_id.to_string(),
                    rule_name: rule.name.clone(),
                    action: rule.action,
                    current_value: avg,
                    threshold: rule.threshold,
                });
            }
        }
        
        decisions
    }

    /// Forecast capacity needs
    pub fn forecast(&self, pop_id: &str, hours_ahead: u32) -> Option<CapacityForecast> {
        let samples = self.metrics.get(pop_id)?;
        
        // Simple linear regression for trend
        let cpu_samples: Vec<_> = samples.iter()
            .filter(|s| s.metric == MetricType::CpuUtilization)
            .collect();
        
        if cpu_samples.len() < 10 { return None; }
        
        let (slope, intercept) = linear_regression(&cpu_samples);
        
        let now_ts = now();
        let future_ts = now_ts + (hours_ahead as u64 * 3600);
        let predicted_cpu = slope * future_ts as f64 + intercept;
        
        Some(CapacityForecast {
            pop_id: pop_id.to_string(),
            hours_ahead,
            predicted_cpu: predicted_cpu.clamp(0.0, 100.0),
            needs_scaling: predicted_cpu > 70.0,
            confidence: if cpu_samples.len() > 50 { 0.8 } else { 0.5 },
        })
    }

    /// Get capacity alerts
    pub fn get_alerts(&self) -> Vec<CapacityAlert> {
        let mut alerts = Vec::new();
        
        for (pop_id, samples) in &self.metrics {
            let decisions = self.evaluate(pop_id);
            for decision in decisions {
                if matches!(decision.action, ScalingAction::ScaleUp | ScalingAction::AddPop) {
                    alerts.push(CapacityAlert {
                        pop_id: pop_id.clone(),
                        severity: AlertSeverity::Warning,
                        message: format!("{}: {} at {:.1}% (threshold: {:.1}%)",
                            decision.rule_name, decision.action.display(),
                            decision.current_value, decision.threshold),
                        timestamp: now(),
                    });
                }
            }
        }
        
        alerts
    }
}

impl Default for CapacityPlanner {
    fn default() -> Self { Self::new() }
}

fn linear_regression(samples: &[&MetricSample]) -> (f64, f64) {
    let n = samples.len() as f64;
    let sum_x: f64 = samples.iter().map(|s| s.timestamp as f64).sum();
    let sum_y: f64 = samples.iter().map(|s| s.value).sum();
    let sum_xy: f64 = samples.iter().map(|s| s.timestamp as f64 * s.value).sum();
    let sum_xx: f64 = samples.iter().map(|s| (s.timestamp as f64).powi(2)).sum();
    
    let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x.powi(2));
    let intercept = (sum_y - slope * sum_x) / n;
    
    (slope, intercept)
}

#[derive(Debug, Clone)]
pub struct MetricSample {
    pub metric: MetricType,
    pub value: f64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    CpuUtilization,
    MemoryUtilization,
    BandwidthUtilization,
    ActiveFlows,
    Latency,
    PacketLoss,
}

#[derive(Debug, Clone)]
pub struct ScalingRule {
    pub name: String,
    pub metric: MetricType,
    pub threshold: f64,
    pub action: ScalingAction,
    pub cooldown_secs: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum ScalingAction {
    ScaleUp,
    ScaleDown,
    AddPop,
}

impl ScalingAction {
    pub fn display(&self) -> &'static str {
        match self {
            Self::ScaleUp => "Needs scale-up",
            Self::ScaleDown => "Can scale-down",
            Self::AddPop => "Needs new PoP",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScalingDecision {
    pub pop_id: String,
    pub rule_name: String,
    pub action: ScalingAction,
    pub current_value: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone)]
pub struct CapacityForecast {
    pub pop_id: String,
    pub hours_ahead: u32,
    pub predicted_cpu: f64,
    pub needs_scaling: bool,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct CapacityAlert {
    pub pop_id: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scaling_rules() {
        let mut planner = CapacityPlanner::new();
        
        // Record high CPU
        for _ in 0..10 {
            planner.record_metric("pop-1", MetricType::CpuUtilization, 85.0);
        }
        
        let decisions = planner.evaluate("pop-1");
        assert!(!decisions.is_empty());
        assert!(decisions.iter().any(|d| matches!(d.action, ScalingAction::ScaleUp)));
    }
}
