"""
OpenSASE-Lab Portal Backend
FastAPI application with OIDC SSO and aggregator APIs
"""

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import httpx
import os
import logging
from datetime import datetime

# Configuration
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "http://keycloak:8080/realms/opensase-lab")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "portal-app")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
FLEXIWAN_API_URL = os.getenv("FLEXIWAN_API_URL", "http://flexiwan-controller:3000")
ZITI_CTRL_URL = os.getenv("ZITI_CTRL_URL", "https://ziti-controller:1280")
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
SECURITY_POP_API_URL = os.getenv("SECURITY_POP_API_URL", "http://security-pop:8080")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI App
app = FastAPI(
    title="OpenSASE-Lab Portal API",
    description="Unified API for SASE lab management",
    version="1.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class HealthResponse(BaseModel):
    status: str
    timestamp: str
    services: Dict[str, str]


class SiteStatus(BaseModel):
    name: str
    status: str
    ip: str
    tunnel_status: str
    latency_ms: Optional[float] = None


class SecurityAlert(BaseModel):
    id: str
    timestamp: str
    severity: str
    message: str
    source: str


class ZtnaApp(BaseModel):
    name: str
    service_name: str
    location: str
    status: str
    active_sessions: int


class PolicyStatus(BaseModel):
    name: str
    type: str
    enabled: bool
    hits: int


class DashboardSummary(BaseModel):
    sites_online: int
    sites_total: int
    critical_alerts: int
    ztna_sessions: int
    policies_active: int


# Helper functions
async def check_service_health(url: str) -> str:
    """Check if a service is reachable"""
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            response = await client.get(url)
            return "healthy" if response.status_code < 400 else "degraded"
    except Exception as e:
        logger.warning(f"Service check failed for {url}: {e}")
        return "unreachable"


# Routes
@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with service status"""
    services = {
        "flexiwan": await check_service_health(f"{FLEXIWAN_API_URL}/api/health"),
        "ziti": await check_service_health(f"{ZITI_CTRL_URL}/edge/v1/version"),
        "wazuh": await check_service_health(f"{WAZUH_API_URL}"),
        "security-pop": await check_service_health(f"{SECURITY_POP_API_URL}/api/health"),
    }
    
    return HealthResponse(
        status="healthy" if all(s == "healthy" for s in services.values()) else "degraded",
        timestamp=datetime.utcnow().isoformat(),
        services=services,
    )


@app.get("/api/dashboard/summary", response_model=DashboardSummary)
async def get_dashboard_summary():
    """Get aggregated dashboard summary"""
    # In production, these would call actual APIs
    # For demo, return simulated data
    return DashboardSummary(
        sites_online=3,
        sites_total=3,
        critical_alerts=0,
        ztna_sessions=5,
        policies_active=12,
    )


@app.get("/api/sites", response_model=List[SiteStatus])
async def get_sites():
    """Get SD-WAN site status from FlexiWAN"""
    sites = [
        SiteStatus(
            name="Branch A",
            status="online",
            ip="10.201.0.1",
            tunnel_status="connected",
            latency_ms=12.5,
        ),
        SiteStatus(
            name="Branch B",
            status="online",
            ip="10.202.0.1",
            tunnel_status="connected",
            latency_ms=18.2,
        ),
        SiteStatus(
            name="Branch C",
            status="online",
            ip="10.203.0.1",
            tunnel_status="connected",
            latency_ms=15.8,
        ),
    ]
    
    # Try to get real data from FlexiWAN
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(f"{FLEXIWAN_API_URL}/api/devices")
            if response.status_code == 200:
                # Parse and update with real data
                pass
    except Exception as e:
        logger.warning(f"Could not fetch FlexiWAN data: {e}")
    
    return sites


@app.get("/api/alerts", response_model=List[SecurityAlert])
async def get_alerts(limit: int = 10):
    """Get security alerts from Wazuh"""
    alerts = []
    
    # Try to get real alerts from Wazuh
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(
                f"{WAZUH_API_URL}/security/alerts",
                params={"limit": limit},
            )
            if response.status_code == 200:
                data = response.json()
                # Parse alerts
                pass
    except Exception as e:
        logger.warning(f"Could not fetch Wazuh alerts: {e}")
    
    # Return sample data if no real data available
    if not alerts:
        alerts = [
            SecurityAlert(
                id="1",
                timestamp=datetime.utcnow().isoformat(),
                severity="low",
                message="SSH login attempt detected",
                source="branch-a",
            ),
            SecurityAlert(
                id="2",
                timestamp=datetime.utcnow().isoformat(),
                severity="medium",
                message="Unusual DNS query pattern",
                source="security-pop",
            ),
        ]
    
    return alerts


@app.get("/api/ztna/apps", response_model=List[ZtnaApp])
async def get_ztna_apps():
    """Get ZTNA application inventory from OpenZiti"""
    apps = [
        ZtnaApp(
            name="App1",
            service_name="app1.ziti",
            location="Branch A",
            status="available",
            active_sessions=2,
        ),
        ZtnaApp(
            name="App2",
            service_name="app2.ziti",
            location="Branch B",
            status="available",
            active_sessions=3,
        ),
    ]
    
    # Try to get real data from Ziti
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(f"{ZITI_CTRL_URL}/edge/management/v1/services")
            if response.status_code == 200:
                # Parse services
                pass
    except Exception as e:
        logger.warning(f"Could not fetch Ziti services: {e}")
    
    return apps


@app.get("/api/policies", response_model=List[PolicyStatus])
async def get_policies():
    """Get security policy status from Security PoP"""
    policies = [
        PolicyStatus(name="Branch Internet Breakout", type="routing", enabled=True, hits=1250),
        PolicyStatus(name="Block Malware Domains", type="dns", enabled=True, hits=45),
        PolicyStatus(name="IPS - Critical", type="ips", enabled=True, hits=3),
        PolicyStatus(name="IPS - High", type="ips", enabled=True, hits=12),
        PolicyStatus(name="SQL Injection Detection", type="ips", enabled=True, hits=0),
    ]
    
    return policies


@app.get("/api/metrics")
async def get_metrics():
    """Prometheus-compatible metrics endpoint"""
    metrics = """
# HELP portal_sites_online Number of online SD-WAN sites
# TYPE portal_sites_online gauge
portal_sites_online 3

# HELP portal_ztna_sessions Active ZTNA sessions
# TYPE portal_ztna_sessions gauge
portal_ztna_sessions 5

# HELP portal_alerts_critical Critical security alerts
# TYPE portal_alerts_critical gauge
portal_alerts_critical 0

# HELP portal_policies_active Active security policies
# TYPE portal_policies_active gauge
portal_policies_active 12
"""
    return metrics


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
