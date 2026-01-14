"""
QoE Path Selector - Scoring Algorithm
"""

from typing import Dict, List
from .models import (
    ProbeResult, SiteProbes, PathScore, AppClass, WANLink,
    AppClassThresholds
)


# Default thresholds per app class
APP_CLASS_THRESHOLDS = {
    AppClass.VOICE: AppClassThresholds(
        max_latency_ms=150,
        max_jitter_ms=30,
        max_loss_percent=1.0,
        target_bandwidth_mbps=1.0,
        weight_latency=0.5,
        weight_jitter=0.3,
        weight_loss=0.2,
        weight_bandwidth=0.0
    ),
    AppClass.VIDEO: AppClassThresholds(
        max_latency_ms=200,
        max_jitter_ms=50,
        max_loss_percent=2.0,
        target_bandwidth_mbps=10.0,
        weight_latency=0.4,
        weight_jitter=0.3,
        weight_loss=0.2,
        weight_bandwidth=0.1
    ),
    AppClass.WEB: AppClassThresholds(
        max_latency_ms=500,
        max_jitter_ms=100,
        max_loss_percent=5.0,
        target_bandwidth_mbps=5.0,
        weight_latency=0.6,
        weight_jitter=0.1,
        weight_loss=0.2,
        weight_bandwidth=0.1
    ),
    AppClass.BULK: AppClassThresholds(
        max_latency_ms=1000,
        max_jitter_ms=200,
        max_loss_percent=5.0,
        target_bandwidth_mbps=50.0,
        weight_latency=0.2,
        weight_jitter=0.0,
        weight_loss=0.1,
        weight_bandwidth=0.7
    )
}


class PathScorer:
    """
    Computes path scores based on QoE metrics.
    
    Score formula:
    Score = Σ(weight[metric] × normalize(metric_value))
    
    Where normalize maps metric values to 0.0-1.0 range
    (1.0 = best, 0.0 = worst/exceeds threshold)
    """
    
    def __init__(self, thresholds: Dict[AppClass, AppClassThresholds] = None):
        self.thresholds = thresholds or APP_CLASS_THRESHOLDS
    
    def score_path(
        self, 
        probe: ProbeResult, 
        app_class: AppClass
    ) -> PathScore:
        """
        Score a single WAN path for an app class.
        """
        thresholds = self.thresholds[app_class]
        
        # Normalize each metric
        latency_score = self._normalize(
            probe.latency_ms, 
            thresholds.max_latency_ms,
            lower_is_better=True
        )
        
        jitter_score = self._normalize(
            probe.jitter_ms,
            thresholds.max_jitter_ms,
            lower_is_better=True
        )
        
        loss_score = self._normalize(
            probe.loss_percent,
            thresholds.max_loss_percent,
            lower_is_better=True
        )
        
        bandwidth_score = self._normalize(
            probe.bandwidth_mbps or 0,
            thresholds.target_bandwidth_mbps,
            lower_is_better=False
        )
        
        # Calculate weighted score
        score = (
            thresholds.weight_latency * latency_score +
            thresholds.weight_jitter * jitter_score +
            thresholds.weight_loss * loss_score +
            thresholds.weight_bandwidth * bandwidth_score
        )
        
        # Check SLA compliance
        meets_sla = (
            probe.latency_ms <= thresholds.max_latency_ms and
            probe.jitter_ms <= thresholds.max_jitter_ms and
            probe.loss_percent <= thresholds.max_loss_percent
        )
        
        return PathScore(
            site=probe.site,
            wan_link=probe.wan_link,
            app_class=app_class,
            score=round(score, 3),
            breakdown={
                "latency": round(latency_score, 3),
                "jitter": round(jitter_score, 3),
                "loss": round(loss_score, 3),
                "bandwidth": round(bandwidth_score, 3)
            },
            meets_sla=meets_sla
        )
    
    def score_site(
        self, 
        site_probes: SiteProbes, 
        app_class: AppClass
    ) -> Dict[str, PathScore]:
        """
        Score all WAN paths for a site.
        """
        scores = {}
        for wan_link, probe in site_probes.probes.items():
            scores[wan_link] = self.score_path(probe, app_class)
        return scores
    
    def score_all(
        self, 
        all_probes: Dict[str, SiteProbes],
        app_classes: List[AppClass] = None
    ) -> Dict[str, Dict[str, Dict[str, PathScore]]]:
        """
        Score all sites and all app classes.
        
        Returns:
            {site: {app_class: {wan_link: PathScore}}}
        """
        app_classes = app_classes or list(AppClass)
        results = {}
        
        for site, site_probes in all_probes.items():
            results[site] = {}
            for app_class in app_classes:
                results[site][app_class.value] = self.score_site(site_probes, app_class)
        
        return results
    
    def _normalize(
        self, 
        value: float, 
        threshold: float,
        lower_is_better: bool = True
    ) -> float:
        """
        Normalize a metric value to 0.0-1.0 range.
        """
        if threshold <= 0:
            return 1.0
        
        if lower_is_better:
            # 0 = perfect (1.0), threshold = minimum acceptable (0.0)
            normalized = max(0, 1 - (value / threshold))
        else:
            # 0 = worst (0.0), threshold = target (1.0)
            normalized = min(1, value / threshold)
        
        return normalized
    
    def get_best_path(
        self, 
        site_probes: SiteProbes, 
        app_class: AppClass
    ) -> tuple[WANLink, PathScore]:
        """
        Get the best WAN path for an app class.
        """
        scores = self.score_site(site_probes, app_class)
        
        # Sort by score (descending)
        sorted_paths = sorted(
            scores.items(),
            key=lambda x: x[1].score,
            reverse=True
        )
        
        if sorted_paths:
            best_link = WANLink(sorted_paths[0][0])
            return best_link, sorted_paths[0][1]
        
        return WANLink.WAN1, PathScore(
            site=site_probes.site,
            wan_link=WANLink.WAN1,
            app_class=app_class,
            score=0.0
        )
