"""
CASB-lite - Base Connector Interface
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime, timedelta
from ..models import (
    NormalizedEvent, RiskySignIn, SaaSUser, SaaSApp,
    Provider, ConnectorStatus, SyncResult
)


class BaseConnector(ABC):
    """
    Base interface for SaaS connectors.
    """
    
    @property
    @abstractmethod
    def provider(self) -> Provider:
        """Provider name."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name."""
        pass
    
    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to provider.
        
        Returns:
            True if connected successfully
        """
        pass
    
    @abstractmethod
    async def get_status(self) -> ConnectorStatus:
        """Get connector status."""
        pass
    
    @abstractmethod
    async def fetch_events(
        self, 
        since: Optional[datetime] = None,
        until: Optional[datetime] = None
    ) -> List[NormalizedEvent]:
        """
        Fetch audit events from provider.
        
        Args:
            since: Start time (default: 24h ago)
            until: End time (default: now)
            
        Returns:
            List of normalized events
        """
        pass
    
    @abstractmethod
    async def fetch_risky_signins(
        self,
        since: Optional[datetime] = None
    ) -> List[RiskySignIn]:
        """
        Fetch risky sign-in events.
        
        Args:
            since: Start time (default: 24h ago)
            
        Returns:
            List of risky sign-in events
        """
        pass
    
    @abstractmethod
    async def fetch_users(self) -> List[SaaSUser]:
        """
        Fetch user inventory.
        
        Returns:
            List of users
        """
        pass
    
    async def fetch_apps(self) -> List[SaaSApp]:
        """
        Fetch third-party app inventory.
        
        Returns:
            List of apps (empty if not supported)
        """
        return []
    
    async def sync(
        self,
        lookback_hours: int = 24
    ) -> SyncResult:
        """
        Full sync operation.
        """
        import time
        start = time.time()
        errors = []
        events = []
        
        since = datetime.now() - timedelta(hours=lookback_hours)
        
        try:
            events = await self.fetch_events(since=since)
        except Exception as e:
            errors.append(f"Event fetch failed: {str(e)}")
        
        try:
            risky = await self.fetch_risky_signins(since=since)
            # Convert risky sign-ins to events
            events.extend(self._risky_to_events(risky))
        except Exception as e:
            errors.append(f"Risky sign-in fetch failed: {str(e)}")
        
        duration = time.time() - start
        
        return SyncResult(
            provider=self.provider,
            success=len(errors) == 0,
            events_fetched=len(events),
            events_normalized=len(events),
            duration_seconds=round(duration, 2),
            errors=errors
        )
    
    def _risky_to_events(self, risky_signins: List[RiskySignIn]) -> List[NormalizedEvent]:
        """Convert risky sign-ins to normalized events."""
        from ..models import EventType
        
        events = []
        for r in risky_signins:
            events.append(NormalizedEvent(
                timestamp=r.timestamp,
                provider=r.provider,
                event_type=EventType.RISKY_SIGNIN,
                user=r.user,
                source_ip=r.source_ip,
                action="risky_signin",
                risk_level=r.risk_level,
                details={
                    "location": r.location,
                    "risk_reasons": r.risk_reasons,
                    "action_taken": r.action_taken
                }
            ))
        return events
