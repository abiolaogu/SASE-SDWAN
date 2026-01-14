"""
CASB-lite - Google Workspace Connector
"""

import os
from typing import List, Optional
from datetime import datetime, timedelta
from .base import BaseConnector
from ..models import (
    Provider, NormalizedEvent, RiskySignIn, SaaSUser, SaaSApp,
    ConnectorStatus, EventType, RiskLevel
)


class GoogleWorkspaceConnector(BaseConnector):
    """
    Connector for Google Workspace.
    
    Uses:
    - Admin SDK Reports API for audit logs
    - Admin SDK Directory API for users
    - Alert Center API for risky sign-ins
    
    Required scopes:
    - https://www.googleapis.com/auth/admin.reports.audit.readonly
    - https://www.googleapis.com/auth/admin.directory.user.readonly
    """
    
    provider = Provider.GOOGLE_WORKSPACE
    name = "Google Workspace"
    
    def __init__(
        self, 
        credentials_path: str = None,
        subject_email: str = None
    ):
        self.credentials_path = credentials_path or os.getenv("GOOGLE_CREDENTIALS")
        self.subject_email = subject_email or os.getenv("GOOGLE_SUBJECT_EMAIL")
        self._connected = False
        self._last_sync: Optional[datetime] = None
        self._events_synced = 0
    
    async def connect(self) -> bool:
        """Establish connection to Google Workspace."""
        # In production, would use google-auth and googleapiclient
        # For demo, simulate connection
        if self.credentials_path and os.path.exists(self.credentials_path):
            self._connected = True
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
        """Fetch audit events from Google Workspace."""
        since = since or datetime.now() - timedelta(hours=24)
        until = until or datetime.now()
        
        # In production, use Reports API
        # activities = reports_service.activities().list(
        #     userKey='all',
        #     applicationName='login',
        #     startTime=since.isoformat(),
        #     endTime=until.isoformat()
        # ).execute()
        
        # Demo: Return simulated events
        return self._simulate_events(since, until)
    
    async def fetch_risky_signins(
        self,
        since: Optional[datetime] = None
    ) -> List[RiskySignIn]:
        """Fetch risky sign-ins from Alert Center."""
        since = since or datetime.now() - timedelta(hours=24)
        
        # Demo: Return simulated risky sign-ins
        return [
            RiskySignIn(
                id="gw-risky-001",
                timestamp=datetime.now() - timedelta(hours=2),
                provider=self.provider,
                user="user@example.com",
                source_ip="192.168.1.100",
                location="Unknown Location",
                risk_level=RiskLevel.MEDIUM,
                risk_reasons=["Unusual location", "New device"],
                action_taken="MFA required"
            )
        ]
    
    async def fetch_users(self) -> List[SaaSUser]:
        """Fetch user inventory from Directory API."""
        # Demo: Return simulated users
        return [
            SaaSUser(
                id="gw-user-001",
                email="admin@example.com",
                display_name="Admin User",
                provider=self.provider,
                is_admin=True,
                is_active=True,
                mfa_enabled=True,
                groups=["admins", "all-users"]
            ),
            SaaSUser(
                id="gw-user-002",
                email="employee@example.com",
                display_name="Employee User",
                provider=self.provider,
                is_admin=False,
                is_active=True,
                mfa_enabled=True,
                groups=["employees", "all-users"]
            )
        ]
    
    async def fetch_apps(self) -> List[SaaSApp]:
        """Fetch third-party apps."""
        return [
            SaaSApp(
                id="gw-app-001",
                name="Slack",
                provider=self.provider,
                permissions=["read_email", "access_calendar"],
                user_count=45,
                risk_score=0.2
            ),
            SaaSApp(
                id="gw-app-002",
                name="Zoom",
                provider=self.provider,
                permissions=["access_calendar", "read_contacts"],
                user_count=50,
                risk_score=0.1
            )
        ]
    
    def _simulate_events(
        self, 
        since: datetime, 
        until: datetime
    ) -> List[NormalizedEvent]:
        """Generate simulated events for demo."""
        events = []
        
        # Simulate login events
        events.append(NormalizedEvent(
            timestamp=datetime.now() - timedelta(hours=1),
            provider=self.provider,
            event_type=EventType.LOGIN,
            user="employee@example.com",
            source_ip="192.168.1.50",
            app="Gmail",
            action="login_success",
            risk_level=RiskLevel.LOW
        ))
        
        events.append(NormalizedEvent(
            timestamp=datetime.now() - timedelta(hours=3),
            provider=self.provider,
            event_type=EventType.FILE_SHARE,
            user="employee@example.com",
            source_ip="192.168.1.50",
            app="Google Drive",
            action="share_external",
            target="report.pdf",
            risk_level=RiskLevel.MEDIUM,
            details={"shared_with": "external@other.com"}
        ))
        
        events.append(NormalizedEvent(
            timestamp=datetime.now() - timedelta(hours=5),
            provider=self.provider,
            event_type=EventType.ADMIN_ACTION,
            user="admin@example.com",
            source_ip="192.168.1.10",
            app="Admin Console",
            action="user_created",
            target="newuser@example.com",
            risk_level=RiskLevel.LOW
        ))
        
        self._last_sync = datetime.now()
        self._events_synced += len(events)
        
        return events
