"""
Unified Policy Orchestrator (UPO) - Data Models
Pydantic models for intent policies and compiled outputs
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal
from enum import Enum


class InspectionLevel(str, Enum):
    """Traffic inspection level."""
    FULL = "full"
    METADATA = "metadata"
    NONE = "none"


class EgressAction(str, Enum):
    """Egress routing action."""
    ROUTE_VIA_POP = "route-via-pop"
    LOCAL_BREAKOUT = "local-breakout"
    DROP = "drop"


class AccessAction(str, Enum):
    """Access rule action."""
    ALLOW = "allow"
    DENY = "deny"
    INSPECT = "inspect"


# ============================================
# Policy Input Models
# ============================================

class UserGroup(BaseModel):
    """User or group definition."""
    name: str
    type: Literal["user", "group"] = "group"
    attributes: List[Dict[str, str]] = []


class Application(BaseModel):
    """Application definition."""
    name: str
    address: str
    port: int = 80
    protocol: str = "tcp"
    segment: str
    inspection: InspectionLevel = InspectionLevel.FULL


class Segment(BaseModel):
    """Network segment definition."""
    name: str
    vlan: int
    vrf_id: int
    description: str = ""


class EgressPolicy(BaseModel):
    """Egress policy for a segment."""
    action: EgressAction
    inspection: InspectionLevel = InspectionLevel.NONE
    preferred_wan: str = "wan1"


class AccessConditions(BaseModel):
    """Conditions for access rules."""
    time_window: Optional[str] = None
    source_segment: Optional[str] = None
    geo_location: Optional[List[str]] = None


class AccessRule(BaseModel):
    """Access control rule."""
    name: str
    users: List[str]
    apps: List[str]
    action: AccessAction
    priority: int = 100
    conditions: Optional[AccessConditions] = None


class Policy(BaseModel):
    """Complete intent policy."""
    name: str
    version: str = "1.0"
    description: str = ""
    users: List[UserGroup] = []
    apps: List[Application] = []
    segments: List[Segment] = []
    egress: Dict[str, EgressPolicy] = {}
    access_rules: List[AccessRule] = []

    class Config:
        extra = "allow"


# ============================================
# Compiled Output Models
# ============================================

class ValidationError(BaseModel):
    """Validation error detail."""
    field: str
    message: str
    severity: Literal["error", "warning"] = "error"


class ValidationResult(BaseModel):
    """Result of policy validation."""
    valid: bool
    errors: List[ValidationError] = []
    warnings: List[ValidationError] = []


class CompiledConfig(BaseModel):
    """Single compiled configuration."""
    target: str
    config_type: str
    content: Any
    description: str = ""


class CompiledOutput(BaseModel):
    """Complete compiled output for an adapter."""
    adapter: str
    policy_name: str
    policy_version: str
    configs: List[CompiledConfig] = []
    metadata: Dict[str, Any] = {}


class ApplyChange(BaseModel):
    """Single change applied to target system."""
    resource_type: str
    resource_name: str
    action: Literal["create", "update", "delete", "skip"]
    details: str = ""


class ApplyResult(BaseModel):
    """Result of applying compiled config."""
    adapter: str
    success: bool
    dry_run: bool = False
    changes: List[ApplyChange] = []
    errors: List[str] = []


# ============================================
# API Request/Response Models
# ============================================

class CompileRequest(BaseModel):
    """Request to compile a policy."""
    policy: Policy
    adapters: Optional[List[str]] = None  # None = all adapters


class CompileResponse(BaseModel):
    """Response from compile endpoint."""
    success: bool
    outputs: List[CompiledOutput] = []
    errors: List[str] = []


class ApplyRequest(BaseModel):
    """Request to apply a policy."""
    policy: Policy
    targets: Optional[List[str]] = None  # None = all
    dry_run: bool = False


class ApplyResponse(BaseModel):
    """Response from apply endpoint."""
    success: bool
    results: List[ApplyResult] = []
    errors: List[str] = []


class AdapterInfo(BaseModel):
    """Information about an adapter."""
    name: str
    description: str
    enabled: bool
    capabilities: List[str] = []
