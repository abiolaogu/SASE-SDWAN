"""
QoE Path Selector - Data Models
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from enum import Enum
from datetime import datetime


class AppClass(str, Enum):
    """Application traffic class."""
    VOICE = "voice"
    VIDEO = "video"
    WEB = "web"
    BULK = "bulk"


class WANLink(str, Enum):
    """WAN link identifier."""
    WAN1 = "wan1"
    WAN2 = "wan2"


class ProbeType(str, Enum):
    """Type of probe."""
    ICMP = "icmp"
    HTTP = "http"
    TCP = "tcp"


# ============================================
# Probe Models
# ============================================

class ProbeResult(BaseModel):
    """Single probe result."""
    site: str
    wan_link: WANLink
    probe_type: ProbeType
    target: str
    timestamp: datetime = Field(default_factory=datetime.now)
    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_percent: float = 0.0
    bandwidth_mbps: Optional[float] = None
    success: bool = True
    error: Optional[str] = None


class SiteProbes(BaseModel):
    """All probe results for a site."""
    site: str
    probes: Dict[str, ProbeResult]  # key: wan_link
    last_updated: datetime = Field(default_factory=datetime.now)


# ============================================
# Scoring Models
# ============================================

class AppClassThresholds(BaseModel):
    """Thresholds for an app class."""
    max_latency_ms: float
    max_jitter_ms: float
    max_loss_percent: float
    target_bandwidth_mbps: float = 10.0
    
    # Weights for scoring
    weight_latency: float = 0.4
    weight_jitter: float = 0.2
    weight_loss: float = 0.3
    weight_bandwidth: float = 0.1


class PathScore(BaseModel):
    """Score for a WAN path."""
    site: str
    wan_link: WANLink
    app_class: AppClass
    score: float  # 0.0 to 1.0
    breakdown: Dict[str, float] = {}
    meets_sla: bool = True
    timestamp: datetime = Field(default_factory=datetime.now)


# ============================================
# Recommendation Models
# ============================================

class SteeringRecommendation(BaseModel):
    """Path steering recommendation."""
    site: str
    app_class: AppClass
    primary_path: WANLink
    backup_path: Optional[WANLink] = None
    primary_score: float
    backup_score: Optional[float] = None
    reason: str
    confidence: float = 1.0  # 0.0 to 1.0
    timestamp: datetime = Field(default_factory=datetime.now)


class RecommendationSet(BaseModel):
    """Complete set of recommendations."""
    recommendations: List[SteeringRecommendation]
    generated_at: datetime = Field(default_factory=datetime.now)
    valid_until: datetime


# ============================================
# Simulation Models
# ============================================

class SimulationScenario(str, Enum):
    """Predefined simulation scenarios."""
    NORMAL = "normal"
    WAN1_CONGESTION = "wan1-congestion"
    WAN2_CONGESTION = "wan2-congestion"
    WAN1_FAILURE = "wan1-failure"
    WAN2_FAILURE = "wan2-failure"
    VARIABLE = "variable"
    FAILOVER = "failover"


class SimulationConfig(BaseModel):
    """Configuration for simulation."""
    scenario: SimulationScenario
    duration_seconds: int = 60
    sites: List[str] = ["branch-a", "branch-b"]
    update_interval_seconds: int = 5


class SimulationState(BaseModel):
    """Current simulation state."""
    active: bool = False
    scenario: Optional[SimulationScenario] = None
    elapsed_seconds: int = 0
    events: List[str] = []


# ============================================
# API Models
# ============================================

class ProbeRequest(BaseModel):
    """Request to run probes."""
    sites: Optional[List[str]] = None
    wan_links: Optional[List[WANLink]] = None


class ScoreRequest(BaseModel):
    """Request for path scores."""
    sites: Optional[List[str]] = None
    app_classes: Optional[List[AppClass]] = None


class SimulateRequest(BaseModel):
    """Request to start simulation."""
    config: SimulationConfig
