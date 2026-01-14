//! OpenSASE Python SDK

"""
OpenSASE Python SDK

A Python client library for the OpenSASE API.

Usage:
    from opensase import OpenSASEClient
    
    client = OpenSASEClient(api_key="ops_live_xxx")
    
    # List users
    users = client.users.list()
    
    # Create policy
    policy = client.policies.create(
        name="Block Malware",
        action="block",
        conditions=[{"field": "threat_category", "operator": "equals", "value": "malware"}]
    )
"""

import os
import requests
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class User:
    id: str
    email: str
    name: str
    role: str
    mfa_enabled: bool
    status: str


@dataclass  
class Policy:
    id: str
    name: str
    description: str
    enabled: bool
    priority: int
    action: str


@dataclass
class Site:
    id: str
    name: str
    location: str
    status: str


class OpenSASEClient:
    """OpenSASE API Client"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.opensase.io/v1"
    ):
        self.api_key = api_key or os.environ.get("OPENSASE_API_KEY")
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "opensase-python/0.1.0"
        })
        
        # Resource clients
        self.users = UsersClient(self)
        self.policies = PoliciesClient(self)
        self.sites = SitesClient(self)
        self.tunnels = TunnelsClient(self)
        self.analytics = AnalyticsClient(self)
    
    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()


class UsersClient:
    def __init__(self, client: OpenSASEClient):
        self._client = client
    
    def list(self, page: int = 1, per_page: int = 20) -> List[User]:
        data = self._client._request("GET", "/users", params={"page": page, "per_page": per_page})
        return [User(**u) for u in data.get("data", {}).get("items", [])]
    
    def get(self, user_id: str) -> User:
        data = self._client._request("GET", f"/users/{user_id}")
        return User(**data.get("data", {}))
    
    def create(self, email: str, name: str, role: str = "viewer") -> User:
        data = self._client._request("POST", "/users", json={"email": email, "name": name, "role": role})
        return User(**data.get("data", {}))


class PoliciesClient:
    def __init__(self, client: OpenSASEClient):
        self._client = client
    
    def list(self) -> List[Policy]:
        data = self._client._request("GET", "/policies")
        return [Policy(**p) for p in data.get("data", {}).get("items", [])]
    
    def get(self, policy_id: str) -> Policy:
        data = self._client._request("GET", f"/policies/{policy_id}")
        return Policy(**data.get("data", {}))
    
    def create(self, name: str, action: str, conditions: List[Dict], priority: int = 100) -> Policy:
        data = self._client._request("POST", "/policies", json={
            "name": name, "action": action, "conditions": conditions, "priority": priority
        })
        return Policy(**data.get("data", {}))


class SitesClient:
    def __init__(self, client: OpenSASEClient):
        self._client = client
    
    def list(self) -> List[Site]:
        data = self._client._request("GET", "/sites")
        return [Site(**s) for s in data.get("data", {}).get("items", [])]


class TunnelsClient:
    def __init__(self, client: OpenSASEClient):
        self._client = client
    
    def list(self) -> List[Dict]:
        data = self._client._request("GET", "/tunnels")
        return data.get("data", {}).get("items", [])
    
    def stats(self, tunnel_id: str) -> Dict:
        data = self._client._request("GET", f"/tunnels/{tunnel_id}/stats")
        return data.get("data", {})


class AnalyticsClient:
    def __init__(self, client: OpenSASEClient):
        self._client = client
    
    def traffic(self, period: str = "24h") -> Dict:
        data = self._client._request("GET", "/analytics/traffic", params={"period": period})
        return data.get("data", {})
    
    def threats(self, period: str = "24h") -> Dict:
        data = self._client._request("GET", "/analytics/threats", params={"period": period})
        return data.get("data", {})
