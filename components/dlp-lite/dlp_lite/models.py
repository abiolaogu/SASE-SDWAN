"""
DLP-lite - Data Models
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    """DLP alert severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ClassifierType(str, Enum):
    """Type of classifier."""
    REGEX = "regex"
    CHECKSUM = "checksum"
    ENTROPY = "entropy"
    KEYWORD = "keyword"
    COMPOUND = "compound"


class ScanSource(str, Enum):
    """Source of scanned content."""
    TEXT = "text"
    FILE = "file"
    PROXY_LOG = "proxy_log"
    API = "api"


# ============================================
# Classifier Models
# ============================================

class ClassifierConfig(BaseModel):
    """Configuration for a classifier."""
    name: str
    description: str
    classifier_type: ClassifierType
    pattern: Optional[str] = None
    keywords: Optional[List[str]] = None
    entropy_threshold: Optional[float] = None
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    context_required: bool = False
    context_patterns: List[str] = []


class ClassifierMatch(BaseModel):
    """A single classifier match."""
    classifier_name: str
    severity: Severity
    matched_text: str
    masked_text: str  # Redacted version
    position: int
    length: int
    confidence: float = 1.0
    context: str = ""


# ============================================
# Scan Models
# ============================================

class ScanRequest(BaseModel):
    """Request to scan content."""
    content: str
    source: ScanSource = ScanSource.TEXT
    filename: Optional[str] = None
    classifiers: Optional[List[str]] = None  # None = all


class ScanResult(BaseModel):
    """Result of scanning content."""
    source: ScanSource
    filename: Optional[str] = None
    content_length: int
    scan_time_ms: float
    matches: List[ClassifierMatch] = []
    highest_severity: Optional[Severity] = None
    has_sensitive_data: bool = False


# ============================================
# Alert Models
# ============================================

class DLPAlert(BaseModel):
    """DLP alert for SIEM."""
    id: str = Field(default_factory=lambda: datetime.now().strftime("%Y%m%d%H%M%S%f"))
    timestamp: datetime = Field(default_factory=datetime.now)
    source: ScanSource
    filename: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    classifier_name: str
    severity: Severity
    matched_count: int
    sample: str  # Masked sample of match
    context: str = ""
    action_taken: str = "logged"
    metadata: Dict[str, Any] = {}


class AlertExportConfig(BaseModel):
    """Configuration for alert export."""
    destination: str  # "wazuh", "opensearch", "file"
    endpoint: Optional[str] = None
    batch_size: int = 100


# ============================================
# Proxy Log Models
# ============================================

class ProxyLogEntry(BaseModel):
    """Parsed proxy log entry."""
    timestamp: datetime
    client_ip: str
    method: str
    url: str
    status_code: int
    bytes_transferred: int
    user: Optional[str] = None
    content_type: Optional[str] = None
    request_body: Optional[str] = None
    response_body: Optional[str] = None


class ProxyLogScanResult(BaseModel):
    """Result of scanning proxy logs."""
    entries_scanned: int
    entries_with_matches: int
    alerts_generated: List[DLPAlert]
    scan_time_seconds: float
