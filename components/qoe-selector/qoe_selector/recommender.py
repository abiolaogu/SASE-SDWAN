"""
QoE Path Selector - Steering Recommender
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .models import (
    SiteProbes, SteeringRecommendation, RecommendationSet,
    AppClass, WANLink, PathScore
)
from .scorer import PathScorer


class SteeringRecommender:
    """
    Generates path steering recommendations based on scores.
    """
    
    def __init__(
        self, 
        scorer: PathScorer = None,
        score_threshold: float = 0.8,
        failover_threshold: float = 0.5
    ):
        self.scorer = scorer or PathScorer()
        self.score_threshold = score_threshold
        self.failover_threshold = failover_threshold
        self._last_recommendations: Dict[str, SteeringRecommendation] = {}
    
    def recommend(
        self, 
        site_probes: SiteProbes,
        app_class: AppClass
    ) -> SteeringRecommendation:
        """
        Generate steering recommendation for a site and app class.
        """
        scores = self.scorer.score_site(site_probes, app_class)
        
        # Sort paths by score
        sorted_paths = sorted(
            [(k, v) for k, v in scores.items()],
            key=lambda x: x[1].score,
            reverse=True
        )
        
        if len(sorted_paths) < 1:
            return self._default_recommendation(site_probes.site, app_class)
        
        primary = sorted_paths[0]
        primary_link = WANLink(primary[0])
        primary_score = primary[1]
        
        backup = sorted_paths[1] if len(sorted_paths) > 1 else None
        backup_link = WANLink(backup[0]) if backup else None
        backup_score = backup[1] if backup else None
        
        # Determine reason
        reason = self._generate_reason(primary_score, backup_score, scores)
        
        # Calculate confidence
        confidence = self._calculate_confidence(primary_score, backup_score)
        
        recommendation = SteeringRecommendation(
            site=site_probes.site,
            app_class=app_class,
            primary_path=primary_link,
            backup_path=backup_link,
            primary_score=primary_score.score,
            backup_score=backup_score.score if backup_score else None,
            reason=reason,
            confidence=confidence
        )
        
        # Store for history
        key = f"{site_probes.site}:{app_class.value}"
        self._last_recommendations[key] = recommendation
        
        return recommendation
    
    def recommend_all(
        self, 
        all_probes: Dict[str, SiteProbes],
        app_classes: List[AppClass] = None,
        validity_minutes: int = 5
    ) -> RecommendationSet:
        """
        Generate recommendations for all sites and app classes.
        """
        app_classes = app_classes or list(AppClass)
        recommendations = []
        
        for site, probes in all_probes.items():
            for app_class in app_classes:
                rec = self.recommend(probes, app_class)
                recommendations.append(rec)
        
        return RecommendationSet(
            recommendations=recommendations,
            generated_at=datetime.now(),
            valid_until=datetime.now() + timedelta(minutes=validity_minutes)
        )
    
    def _generate_reason(
        self, 
        primary: PathScore, 
        backup: Optional[PathScore],
        all_scores: Dict[str, PathScore]
    ) -> str:
        """Generate human-readable reason for recommendation."""
        reasons = []
        
        # Check if primary is significantly better
        if backup and primary.score > backup.score + 0.1:
            score_diff = (primary.score - backup.score) * 100
            reasons.append(f"{primary.wan_link.value} scores {score_diff:.0f}% higher")
        
        # Add specific metric reasons
        breakdown = primary.breakdown
        if breakdown.get("latency", 0) > 0.9:
            reasons.append("excellent latency")
        if breakdown.get("jitter", 0) > 0.9:
            reasons.append("stable connection")
        if breakdown.get("loss", 0) > 0.95:
            reasons.append("minimal packet loss")
        
        # SLA compliance
        if primary.meets_sla:
            reasons.append("meets SLA")
        elif backup and not backup.meets_sla:
            reasons.append("best available (neither meets SLA)")
        
        if reasons:
            return "; ".join(reasons[:3])
        
        return f"{primary.wan_link.value} has best overall score"
    
    def _calculate_confidence(
        self, 
        primary: PathScore, 
        backup: Optional[PathScore]
    ) -> float:
        """
        Calculate confidence in recommendation.
        
        High confidence when:
        - Primary score is high
        - Large gap between primary and backup
        - SLA is met
        """
        confidence = primary.score
        
        if backup:
            # Boost confidence if large gap
            gap = primary.score - backup.score
            if gap > 0.2:
                confidence = min(1.0, confidence + 0.1)
            elif gap < 0.05:
                # Low confidence if scores are similar
                confidence = max(0.5, confidence - 0.2)
        
        if not primary.meets_sla:
            confidence = max(0.3, confidence - 0.3)
        
        return round(confidence, 2)
    
    def _default_recommendation(
        self, 
        site: str, 
        app_class: AppClass
    ) -> SteeringRecommendation:
        """Return default recommendation when no data available."""
        return SteeringRecommendation(
            site=site,
            app_class=app_class,
            primary_path=WANLink.WAN1,
            backup_path=WANLink.WAN2,
            primary_score=0.5,
            backup_score=0.5,
            reason="Using default configuration (no probe data)",
            confidence=0.3
        )
    
    def get_last_recommendation(
        self, 
        site: str, 
        app_class: AppClass
    ) -> Optional[SteeringRecommendation]:
        """Get last recommendation for a site and app class."""
        key = f"{site}:{app_class.value}"
        return self._last_recommendations.get(key)
    
    def should_failover(
        self, 
        current_path: WANLink,
        site_probes: SiteProbes,
        app_class: AppClass
    ) -> tuple[bool, Optional[WANLink]]:
        """
        Check if failover is recommended.
        
        Returns:
            (should_failover, new_path)
        """
        scores = self.scorer.score_site(site_probes, app_class)
        current_score = scores.get(current_path.value)
        
        if not current_score:
            return True, WANLink.WAN1 if current_path == WANLink.WAN2 else WANLink.WAN2
        
        # Check if current path is below threshold
        if current_score.score < self.failover_threshold:
            best_link, best_score = self.scorer.get_best_path(site_probes, app_class)
            if best_score.score > current_score.score + 0.1:
                return True, best_link
        
        return False, None
