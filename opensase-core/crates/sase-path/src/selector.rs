//! Path selector combining probes and scoring

use crate::{
    WanLink, PathRecommendation, QoEWeights,
    probes::{ProbeCollector, ProbeResult},
    scorer::{PathScorer, PathScore},
};
use sase_common::{AppClass, Timestamp};
use std::sync::Arc;
use std::time::Duration;

/// Path selector with recommendation engine
pub struct PathSelector {
    /// Probe collector
    probes: Arc<ProbeCollector>,
    /// Path scorer
    scorer: PathScorer,
    /// Hysteresis threshold (prevent flapping)
    hysteresis: f32,
}

impl PathSelector {
    /// Create new path selector
    pub fn new(probes: Arc<ProbeCollector>) -> Self {
        Self {
            probes,
            scorer: PathScorer::new(),
            hysteresis: 0.1,  // 10% improvement required to switch
        }
    }

    /// Set hysteresis threshold
    pub fn with_hysteresis(mut self, hysteresis: f32) -> Self {
        self.hysteresis = hysteresis;
        self
    }

    /// Record a probe result
    #[inline]
    pub fn record_probe(&self, site: &str, wan: WanLink, probe: ProbeResult) {
        self.probes.record(site, wan, probe);
    }

    /// Get path recommendation for site and app class
    /// 
    /// # Performance
    /// Target: <5μs
    pub fn recommend(&self, site: &str, app_class: AppClass) -> PathRecommendation {
        let start = Timestamp::now();
        
        // Get all paths for site
        let paths = self.probes.get_site(site);
        
        if paths.is_empty() {
            return self.default_recommendation(site, app_class);
        }

        // Score and rank
        let ranked = self.scorer.rank_paths(&paths, app_class);

        if ranked.is_empty() {
            return self.default_recommendation(site, app_class);
        }

        let (primary, primary_score) = ranked[0];
        let backup = if ranked.len() > 1 {
            Some(ranked[1].0)
        } else {
            None
        };

        // Generate reason
        let reason = self.generate_reason(&ranked, app_class);

        // Calculate confidence
        let confidence = self.calculate_confidence(&ranked);

        PathRecommendation {
            site: site.to_string(),
            app_class,
            primary,
            backup,
            primary_score: primary_score.score,
            confidence,
            reason,
        }
    }

    /// Check if path switch is recommended
    pub fn should_switch(
        &self,
        current: WanLink,
        site: &str,
        app_class: AppClass,
    ) -> Option<WanLink> {
        let paths = self.probes.get_site(site);
        if paths.is_empty() {
            return None;
        }

        let ranked = self.scorer.rank_paths(&paths, app_class);
        if ranked.is_empty() {
            return None;
        }

        // Find current path score
        let current_score = ranked.iter()
            .find(|(w, _)| *w == current)
            .map(|(_, s)| s.score)
            .unwrap_or(0.0);

        // Check if best path is significantly better
        let (best, best_score) = ranked[0];
        if best != current && best_score.score > current_score + self.hysteresis {
            return Some(best);
        }

        None
    }

    /// Recommend for all app classes
    pub fn recommend_all(&self, site: &str) -> Vec<PathRecommendation> {
        [AppClass::Voice, AppClass::Video, AppClass::Web, AppClass::Bulk]
            .iter()
            .map(|&class| self.recommend(site, class))
            .collect()
    }

    fn default_recommendation(&self, site: &str, app_class: AppClass) -> PathRecommendation {
        PathRecommendation {
            site: site.to_string(),
            app_class,
            primary: WanLink::Wan1,
            backup: Some(WanLink::Wan2),
            primary_score: 0.5,
            confidence: 0.3,
            reason: "Default (no probe data)".to_string(),
        }
    }

    fn generate_reason(&self, ranked: &[(WanLink, PathScore)], _app_class: AppClass) -> String {
        if ranked.is_empty() {
            return "No paths available".to_string();
        }

        let (best, score) = &ranked[0];
        let mut reasons = Vec::new();

        if score.meets_sla {
            reasons.push("meets SLA");
        }
        if score.latency_score > 0.9 {
            reasons.push("excellent latency");
        }
        if score.loss_score > 0.95 {
            reasons.push("minimal loss");
        }

        if reasons.is_empty() {
            format!("{:?} has best score ({:.2})", best, score.score)
        } else {
            format!("{:?}: {}", best, reasons.join(", "))
        }
    }

    fn calculate_confidence(&self, ranked: &[(WanLink, PathScore)]) -> f32 {
        if ranked.len() < 2 {
            return 0.5;
        }

        let gap = ranked[0].1.score - ranked[1].1.score;
        let base = ranked[0].1.score;

        // Higher confidence with larger gap and higher absolute score
        let mut confidence = base;
        if gap > 0.2 {
            confidence = (confidence + 0.1).min(1.0);
        } else if gap < 0.05 {
            confidence = (confidence - 0.2).max(0.3);
        }

        if !ranked[0].1.meets_sla {
            confidence = (confidence - 0.3).max(0.2);
        }

        confidence
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new(Arc::new(ProbeCollector::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommend() {
        let collector = Arc::new(ProbeCollector::default());
        let selector = PathSelector::new(collector.clone());

        // Add probes
        selector.record_probe("site-a", WanLink::Wan1, 
            ProbeResult::success(15_000, 3_000, 5, 100_000));
        selector.record_probe("site-a", WanLink::Wan2, 
            ProbeResult::success(45_000, 8_000, 10, 50_000));

        let rec = selector.recommend("site-a", AppClass::Voice);
        assert_eq!(rec.primary, WanLink::Wan1);
        assert!(rec.primary_score > 0.5);
    }

    #[test]
    fn test_should_switch() {
        let collector = Arc::new(ProbeCollector::default());
        let selector = PathSelector::new(collector.clone());

        // WAN1 is significantly worse
        selector.record_probe("site-a", WanLink::Wan1, 
            ProbeResult::success(200_000, 50_000, 50, 10_000));
        selector.record_probe("site-a", WanLink::Wan2, 
            ProbeResult::success(15_000, 3_000, 5, 100_000));

        let switch = selector.should_switch(WanLink::Wan1, "site-a", AppClass::Voice);
        assert_eq!(switch, Some(WanLink::Wan2));
    }

    #[test]
    fn test_performance() {
        let collector = Arc::new(ProbeCollector::default());
        let selector = PathSelector::new(collector.clone());

        // Add probes
        for i in 0..100 {
            selector.record_probe(&format!("site-{}", i), WanLink::Wan1,
                ProbeResult::success(15_000, 3_000, 5, 100_000));
            selector.record_probe(&format!("site-{}", i), WanLink::Wan2,
                ProbeResult::success(45_000, 8_000, 10, 50_000));
        }

        let start = std::time::Instant::now();
        for _ in 0..100_000 {
            let _ = selector.recommend("site-50", AppClass::Voice);
        }
        let elapsed = start.elapsed();

        let avg_us = elapsed.as_micros() as f64 / 100_000.0;
        println!("Average recommend time: {:.2}μs", avg_us);

        // Should be <5μs
        assert!(avg_us < 5.0);
    }
}
