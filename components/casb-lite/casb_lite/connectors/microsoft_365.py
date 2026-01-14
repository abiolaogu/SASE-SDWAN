"""
CASB-lite - Microsoft 365 Connector
"""

import os
from typing import List, Optional
from datetime import datetime, timedelta
from .base import BaseConnector
from ..models import (
    Provider, NormalizedEvent, RiskySignIn, SaaSUser, SaaSApp,
    ConnectorStatus, EventType, RiskLevel
)


class Microsoft365Connector(BaseConnector):
    """
    Connector for Microsoft 365.
    
    Uses:
    - Microsoft Graph API for unified audit logs
    - Azure AD Identity Protection for risky sign-ins
    - Microsoft Graph for user directory
    
    Required permissions:
    - AuditLog.Read.All
    - Directory.Read.All
    - IdentityRiskyUser.Read.All
    """
    
    provider = Provider.MICROSOFT_365
    name = "Microsoft 365"
    
    def __init__(
        self, 
        client_id: str = None,
        client_secret: str = None,
        tenant_id: str = None
    ):
        self.client_id = client_id or os.getenv("MS365_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("MS365_CLIENT_SECRET")
        self.tenant_id = tenant_id or os.getenv("MS365_TENANT_ID")
        self._connected = False
        self._last_sync: Optional[datetime] = None
        self._events_synced = 0
        self._access_token: Optional[str] = None
    
    async def connect(self) -> bool:
        """Establish connection to Microsoft 365."""
        # In production, would use MSAL for OAuth
        # For demo, simulate connection
        if self.client_id and self.client_secret and self.tenant_id:
            self._connected = True
            self._access_token = "demo-token"
        else:
            # Demo mode - simulate connection
            self._connected = True
        return self._connected
    
    async def get_status(self) -> ConnectorStatus:
        """Get connector status."""
        return ConnectorStatus(
            provider=self.provider,
            connected=self._connected,
            last_sync=self._last_sync,
            events_synced=self._events_synced,
            errors=[]
        )
    
    async def fetch_events(
        self, 
        since: Optional[datetime] = None,
        until: Optional[datetime] = None
    ) -> List[NormalizedEvent]:
        """Fetch audit events from Microsoft 365."""
        since = since or datetime.now() - timedelta(hours=24)
        until = until or datetime.now()
        
        # In production, use Graph API
        # GET /auditLogs/signIns
        # GET /auditLogs/directoryAudits
        
        # Demo: Return simulated events
        return self._simulate_events(since, until)
    
    async def fetch_risky_signins(
        self,
        since: Optional[datetime] = None
    ) -> List[RiskySignIn]:
        """Fetch risky sign-ins from Identity Protection."""
        since = since or datetime.now() - timedelta(hours=24)
        
        # In production, use Identity Protection API
        # GET /identityProtection/riskyUsers
        # GET /identityProtection/riskDetections
        
        # Demo: Return simulated risky sign-ins
        return [
            RiskySignIn(
                id="ms-risky-001",
                timestamp=datetime.now() - timedelta(hours=4),
                provider=self.provider,
                user="employee@contoso.com",
                source_ip="203.0.113.50",
                location="Unusual country",
                risk_level=RiskLevel.HIGH,
                risk_reasons=["Impossible travel", "Anonymous IP"],
                action_taken="Block and require password change"
            ),
            RiskySignIn(
                id="ms-risky-002",
                timestamp=datetime.now() - timedelta(hours=8),
                provider=self.provider,
                user="contractor@contoso.com",
                source_ip="198.51.100.25",
                location="Unknown",
                risk_level=RiskLevel.MEDIUM,
                risk_reasons=["Unfamiliar sign-in properties"],
                action_taken="MFA challenge"
            )
        ]
    
    async def fetch_users(self) -> List[SaaSUser]:
        """Fetch user inventory from Azure AD."""
        # In production, use Graph API
        # GET /users
        
        # Demo: Return simulated users
        return [
            SaaSUser(
                id="ms-user-001",
                email="admin@contoso.com",
                display_name="Global Admin",
                provider=self.provider,
                is_admin=True,
                is_active=True,
                mfa_enabled=True,
                groups=["Global Admins", "All Users"]
            ),
            SaaSUser(
                id="ms-user-002",
                email="employee@contoso.com",
                display_name="John Employee",
                provider=self.provider,
                is_admin=False,
                is_active=True,
                mfa_enabled=True,
                groups=["Sales", "All Users"]
            ),
            SaaSUser(
                id="ms-user-003",
                email="contractor@contoso.com",
                display_name="External Contractor",
                provider=self.provider,
                is_admin=False,
                is_active=True,
                mfa_enabled=False,  # Risky!
                groups=["Contractors"]
            )
        ]
    
    async def fetch_apps(self) -> List[SaaSApp]:
        """Fetch enterprise applications."""
        return [
            SaaSApp(
                id="ms-app-001",
                name="Salesforce",
                provider=self.provider,
                permissions=["User.Read", "openid"],
                user_count=100,
                risk_score=0.1
            ),
            SaaSApp(
                id="ms-app-002",
                name="ServiceNow",
                provider=self.provider,
                permissions=["User.Read", "Directory.Read.All"],
                user_count=75,
                risk_score=0.15
            ),
            SaaSApp(
                id="ms-app-003",
                name="Unknown App",
                provider=self.provider,
                permissions=["Mail.ReadWrite", "Files.ReadWrite.All"],
                user_count=5,
                risk_score=0.8  # High risk - excessive permissions
            )
        ]
    
    def _simulate_events(
        self, 
        since: datetime, 
        until: datetime
    ) -> List[NormalizedEvent]:
        """Generate simulated events for demo."""
        events = []
        
        # Simulate various events
        events.append(NormalizedEvent(
            timestamp=datetime.now() - timedelta(hours=2),
            provider=self.provider,
            event_type=EventType.LOGIN,
            user="employee@contoso.com",
            source_ip="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            app="Microsoft Teams",
            action="login_success",
            risk_level=RiskLevel.LOW
        ))
        
        events.append(NormalizedEvent(
            timestamp=datetime.now() - timedelta(hours=4),
            provider=self.provider,
            event_type=EventType.FILE_DOWNLOAD,
            user="employee@contoso.com",
            source_ip="192.168.1.100",
            app="OneDrive",
            action="file_downloaded",
            target="confidential-report.xlsx",
            risk_level=RiskLevel.MEDIUM,
            details={"file_size": "2.5 MB", "sensitivity": "Confidential"}
        ))
        
        events.append(NormalizedEvent(
            timestamp=datetime.now() - timedelta(hours=6),
            provider=self.provider,
            event_type=EventType.PERMISSION_CHANGE,
            user="admin@contoso.com",
            source_ip="192.168.1.10",
            app="Azure AD",
            action="role_assigned",
            target="contractor@contoso.com",
            risk_level=RiskLevel.MEDIUM,
            details={"role": "Application Administrator"}
        ))
        
        events.append(NormalizedEvent(
            timestamp=datetime.now() - timedelta(hours=8),
            provider=self.provider,
            event_type=EventType.MFA_CHANGE,
            user="contractor@contoso.com",
            source_ip="198.51.100.25",
            app="Azure AD",
            action="mfa_disabled",
            risk_level=RiskLevel.HIGH,
            details={"reason": "User request"}
        ))
        
        self._last_sync = datetime.now()
        self._events_synced += len(events)
        
        return events
