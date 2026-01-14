//! Path scoring with weighted QoE metrics

use crate::{WanLink, QoEWeights};
use sase_common::AppClass;

/// Score for a single path
#[derive(Debug, Clone, Copy)]
pub struct PathScore {
    /// Overall score (0.0 - 1.0)
    pub score: f32,
    /// Latency component score
    pub latency_score: f32,
    /// Jitter component score
    pub jitter_score: f32,
    /// Loss component score
    pub loss_score: f32,
    /// Bandwidth component score
    pub bandwidth_score: f32,
    /// Whether path meets SLA
    pub meets_sla: bool,
}

impl PathScore {
    /// Create perfect score
    pub const fn perfect() -> Self {
        Self {
            score: 1.0,
            latency_score: 1.0,
            jitter_score: 1.0,
            loss_score: 1.0,
            bandwidth_score: 1.0,
            meets_sla: true,
        }
    }

    /// Create zero score
    pub const fn zero() -> Self {
        Self {
            score: 0.0,
            latency_score: 0.0,
            jitter_score: 0.0,
            loss_score: 0.0,
            bandwidth_score: 0.0,
            meets_sla: false,
        }
    }
}

/// Path scorer with QoE-based scoring
#[derive(Debug)]
pub struct PathScorer {
    /// SLA thresholds per app class
    thresholds: AppClassThresholds,
}

/// Thresholds for SLA compliance
#[derive(Debug, Clone, Copy)]
pub struct AppClassThresholds {
    /// Max latency for voice (μs)
    pub voice_max_latency_us: u32,
    /// Max jitter for voice (μs)
    pub voice_max_jitter_us: u32,
    /// Max loss for voice (permille)
    pub voice_max_loss: u16,
    
    /// Max latency for video (μs)
    pub video_max_latency_us: u32,
    /// Max jitter for video (μs)
    pub video_max_jitter_us: u32,
    /// Max loss for video (permille)
    pub video_max_loss: u16,
    
    /// Max latency for web (μs)
    pub web_max_latency_us: u32,
}

impl Default for AppClassThresholds {
    fn default() -> Self {
        Self {
            voice_max_latency_us: 150_000,  // 150ms
            voice_max_jitter_us: 30_000,    // 30ms
            voice_max_loss: 10,             // 1%
            
            video_max_latency_us: 200_000,  // 200ms
            video_max_jitter_us: 50_000,    // 50ms
            video_max_loss: 20,             // 2%
            
            web_max_latency_us: 500_000,    // 500ms
        }
    }
}

impl PathScorer {
    /// Create new scorer with default thresholds
    pub fn new() -> Self {
        Self {
            thresholds: AppClassThresholds::default(),
        }
    }

    /// Create with custom thresholds
    pub fn with_thresholds(thresholds: AppClassThresholds) -> Self {
        Self { thresholds }
    }

    /// Score a path for an app class
    /// 
    /// # Arguments
    /// * `latency_us` - Round-trip latency in microseconds
    /// * `jitter_us` - Jitter in microseconds
    /// * `loss_permille` - Packet loss in permille (10 = 1%)
    /// * `bandwidth_kbps` - Available bandwidth in Kbps
    /// * `app_class` - Application class
    /// 
    /// # Performance
    /// Target: <1μs per call
    #[inline]
    pub fn score(
        &self,
        latency_us: u32,
        jitter_us: u32,
        loss_permille: u16,
        bandwidth_kbps: u32,
        app_class: AppClass,
    ) -> PathScore {
        let weights = QoEWeights::for_class(app_class);
        let (max_lat, max_jit, max_loss, target_bw) = self.get_thresholds(app_class);

        // Normalize each metric (1.0 = best, 0.0 = worst)
        let latency_score = Self::normalize_lower_better(latency_us, max_lat);
        let jitter_score = Self::normalize_lower_better(jitter_us, max_jit);
        let loss_score = Self::normalize_lower_better(loss_permille as u32, max_loss as u32);
        let bandwidth_score = Self::normalize_higher_better(bandwidth_kbps, target_bw);

        // Weighted average
        let score = weights.latency * latency_score
            + weights.jitter * jitter_score
            + weights.loss * loss_score
            + weights.bandwidth * bandwidth_score;

        // SLA compliance
        let meets_sla = latency_us <= max_lat
            && jitter_us <= max_jit
            && loss_permille <= max_loss;

        PathScore {
            score,
            latency_score,
            jitter_score,
            loss_score,
            bandwidth_score,
            meets_sla,
        }
    }

    /// Score multiple paths and rank them
    pub fn rank_paths(
        &self,
        paths: &[(WanLink, u32, u32, u16, u32)],  // (wan, lat, jit, loss, bw)
        app_class: AppClass,
    ) -> Vec<(WanLink, PathScore)> {
        let mut scored: Vec<_> = paths
            .iter()
            .map(|(wan, lat, jit, loss, bw)| {
                (*wan, self.score(*lat, *jit, *loss, *bw, app_class))
            })
            .collect();

        // Sort by score (descending)
        scored.sort_by(|a, b| b.1.score.partial_cmp(&a.1.score).unwrap());
        scored
    }

    /// Get thresholds for app class
    fn get_thresholds(&self, app_class: AppClass) -> (u32, u32, u16, u32) {
        match app_class {
            AppClass::Voice | AppClass::Gaming => (
                self.thresholds.voice_max_latency_us,
                self.thresholds.voice_max_jitter_us,
                self.thresholds.voice_max_loss,
                100_000,  // 100 Mbps target
            ),
            AppClass::Video | AppClass::Interactive => (
                self.thresholds.video_max_latency_us,
                self.thresholds.video_max_jitter_us,
                self.thresholds.video_max_loss,
                50_000,  // 50 Mbps target
            ),
            AppClass::Web => (
                self.thresholds.web_max_latency_us,
                100_000,
                50,
                10_000,  // 10 Mbps target
            ),
            AppClass::Bulk | AppClass::Unknown => (
                1_000_000,  // 1 second
                200_000,
                50,
                100_000,  // 100 Mbps target
            ),
        }
    }

    /// Normalize where lower is better
    #[inline(always)]
    fn normalize_lower_better(value: u32, max: u32) -> f32 {
        if max == 0 {
            return 1.0;
        }
        let ratio = value as f32 / max as f32;
        (1.0 - ratio).max(0.0)
    }

    /// Normalize where higher is better
    #[inline(always)]
    fn normalize_higher_better(value: u32, target: u32) -> f32 {
        if target == 0 {
            return 1.0;
        }
        (value as f32 / target as f32).min(1.0)
    }
}

impl Default for PathScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_voice() {
        let scorer = PathScorer::new();
        
        // Good path
        let score = scorer.score(15_000, 3_000, 5, 100_000, AppClass::Voice);
        assert!(score.score > 0.8);
        assert!(score.meets_sla);

        // Bad path
        let score = scorer.score(200_000, 50_000, 50, 10_000, AppClass::Voice);
        assert!(score.score < 0.3);
        assert!(!score.meets_sla);
    }

    #[test]
    fn test_rank_paths() {
        let scorer = PathScorer::new();
        
        let paths = vec![
            (WanLink::Wan1, 15_000, 3_000, 5, 100_000),   // Best
            (WanLink::Wan2, 45_000, 8_000, 10, 50_000),   // Middle
            (WanLink::Lte, 100_000, 20_000, 30, 20_000),  // Worst
        ];

        let ranked = scorer.rank_paths(&paths, AppClass::Voice);
        
        assert_eq!(ranked[0].0, WanLink::Wan1);
        assert_eq!(ranked[1].0, WanLink::Wan2);
        assert_eq!(ranked[2].0, WanLink::Lte);
    }

    #[test]
    fn test_score_performance() {
        let scorer = PathScorer::new();
        
        let start = std::time::Instant::now();
        for _ in 0..1_000_000 {
            let _ = scorer.score(15_000, 3_000, 5, 100_000, AppClass::Voice);
        }
        let elapsed = start.elapsed();
        
        let avg_ns = elapsed.as_nanos() as f64 / 1_000_000.0;
        println!("Average score time: {:.0}ns", avg_ns);
        
        // Should be <100ns
        assert!(avg_ns < 100.0);
    }
}
