"""
CASB-lite - Data Models
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class Provider(str, Enum):
    """SaaS provider."""
    GOOGLE_WORKSPACE = "google-workspace"
    MICROSOFT_365 = "microsoft-365"


class RiskLevel(str, Enum):
    """Risk level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Normalized event types."""
    LOGIN = "login"
    LOGOUT = "logout"
    FILE_ACCESS = "file_access"
    FILE_SHARE = "file_share"
    FILE_DOWNLOAD = "file_download"
    ADMIN_ACTION = "admin_action"
    PERMISSION_CHANGE = "permission_change"
    APP_ACCESS = "app_access"
    RISKY_SIGNIN = "risky_signin"
    MFA_CHANGE = "mfa_change"


# ============================================
# Common Schema Models
# ============================================

class NormalizedEvent(BaseModel):
    """Normalized event in common schema."""
    id: str = Field(default_factory=lambda: datetime.now().strftime("%Y%m%d%H%M%S%f"))
    timestamp: datetime
    provider: Provider
    event_type: EventType
    user: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    app: Optional[str] = None
    action: str
    target: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.LOW
    details: Dict[str, Any] = {}
    raw_event: Optional[Dict[str, Any]] = None


class RiskySignIn(BaseModel):
    """Risky sign-in event."""
    id: str
    timestamp: datetime
    provider: Provider
    user: str
    source_ip: str
    location: Optional[str] = None
    risk_level: RiskLevel
    risk_reasons: List[str] = []
    action_taken: str = "none"


class SaaSUser(BaseModel):
    """User from SaaS provider."""
    id: str
    email: str
    display_name: str
    provider: Provider
    is_admin: bool = False
    is_active: bool = True
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    mfa_enabled: bool = False
    groups: List[str] = []


class SaaSApp(BaseModel):
    """Third-party app from SaaS provider."""
    id: str
    name: str
    provider: Provider
    permissions: List[str] = []
    user_count: int = 0
    risk_score: Optional[float] = None


# ============================================
# Connector Models
# ============================================

class ConnectorConfig(BaseModel):
    """Configuration for a connector."""
    provider: Provider
    enabled: bool = True
    credentials: Dict[str, str] = {}
    sync_interval_minutes: int = 60
    lookback_hours: int = 24


class ConnectorStatus(BaseModel):
    """Status of a connector."""
    provider: Provider
    connected: bool
    last_sync: Optional[datetime] = None
    events_synced: int = 0
    errors: List[str] = []


class SyncResult(BaseModel):
    """Result of a sync operation."""
    provider: Provider
    success: bool
    events_fetched: int = 0
    events_normalized: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = []


# ============================================
# Export Models
# ============================================

class ExportDestination(str, Enum):
    """Export destination."""
    WAZUH = "wazuh"
    OPENSEARCH = "opensearch"
    FILE = "file"


class ExportConfig(BaseModel):
    """Configuration for export."""
    destination: ExportDestination
    endpoint: Optional[str] = None
    batch_size: int = 100


class ExportResult(BaseModel):
    """Result of export operation."""
    destination: ExportDestination
    success: bool
    events_exported: int = 0
    errors: List[str] = []
