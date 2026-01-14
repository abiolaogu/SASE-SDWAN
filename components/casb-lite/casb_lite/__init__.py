"""CASB-lite Package"""

from .models import Provider, NormalizedEvent, RiskySignIn, SaaSUser
from .connectors import CONNECTORS, GoogleWorkspaceConnector, Microsoft365Connector

__version__ = "1.0.0"
__all__ = [
    "Provider", "NormalizedEvent", "RiskySignIn", "SaaSUser",
    "CONNECTORS", "GoogleWorkspaceConnector", "Microsoft365Connector"
]
