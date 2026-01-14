"""CASB-lite Connectors Package"""

from .base import BaseConnector
from .google_workspace import GoogleWorkspaceConnector
from .microsoft_365 import Microsoft365Connector

CONNECTORS = {
    "google-workspace": GoogleWorkspaceConnector,
    "microsoft-365": Microsoft365Connector,
}

__all__ = [
    "BaseConnector",
    "GoogleWorkspaceConnector",
    "Microsoft365Connector",
    "CONNECTORS"
]
