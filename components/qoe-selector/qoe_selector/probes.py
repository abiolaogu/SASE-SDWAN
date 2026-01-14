"""
QoE Path Selector - Probe Collection
"""

import asyncio
import random
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
from .models import ProbeResult, SiteProbes, WANLink, ProbeType


# Default probe targets
DEFAULT_TARGETS = {
    WANLink.WAN1: "8.8.8.8",
    WANLink.WAN2: "1.1.1.1"
}

# Site gateway IPs (in real deployment, discovered dynamically)
SITE_GATEWAYS = {
    "branch-a": {"wan1": "10.201.1.1", "wan2": "10.201.2.1"},
    "branch-b": {"wan1": "10.202.1.1", "wan2": "10.202.2.1"},
    "branch-c": {"wan1": "10.203.1.1", "wan2": "10.203.2.1"},
}


class ProbeCollector:
    """
    Collects network quality probes from WAN links.
    """
    
    def __init__(self, sites: Optional[List[str]] = None):
        self.sites = sites or list(SITE_GATEWAYS.keys())
        self._probe_history: Dict[str, List[ProbeResult]] = {}
        self._use_simulation = True  # Use simulated probes by default
    
    async def collect_all(self) -> Dict[str, SiteProbes]:
        """Collect probes from all sites."""
        results = {}
        
        for site in self.sites:
            results[site] = await self.collect_site(site)
        
        return results
    
    async def collect_site(self, site: str) -> SiteProbes:
        """Collect probes for a specific site."""
        probes = {}
        
        for wan_link in WANLink:
            probe = await self._probe_link(site, wan_link)
            probes[wan_link.value] = probe
            
            # Store in history
            key = f"{site}:{wan_link.value}"
            if key not in self._probe_history:
                self._probe_history[key] = []
            self._probe_history[key].append(probe)
            
            # Keep last 100 probes
            self._probe_history[key] = self._probe_history[key][-100:]
        
        return SiteProbes(site=site, probes=probes)
    
    async def _probe_link(self, site: str, wan_link: WANLink) -> ProbeResult:
        """Execute probe for a specific link."""
        if self._use_simulation:
            return self._simulate_probe(site, wan_link)
        
        target = DEFAULT_TARGETS.get(wan_link, "8.8.8.8")
        
        try:
            # Run ICMP probe
            result = await self._run_icmp_probe(target)
            return ProbeResult(
                site=site,
                wan_link=wan_link,
                probe_type=ProbeType.ICMP,
                target=target,
                **result
            )
        except Exception as e:
            return ProbeResult(
                site=site,
                wan_link=wan_link,
                probe_type=ProbeType.ICMP,
                target=target,
                success=False,
                error=str(e)
            )
    
    async def _run_icmp_probe(self, target: str, count: int = 5) -> dict:
        """Run ICMP ping probe."""
        try:
            # Run ping command
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", str(count), "-W", "2", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            
            # Parse output
            output = stdout.decode()
            
            # Extract stats (simplified parsing)
            latencies = []
            for line in output.split("\n"):
                if "time=" in line:
                    time_part = line.split("time=")[1].split()[0]
                    latencies.append(float(time_part.replace("ms", "")))
            
            if not latencies:
                return {"success": False, "error": "No response"}
            
            avg_latency = sum(latencies) / len(latencies)
            jitter = max(latencies) - min(latencies) if len(latencies) > 1 else 0
            loss = (count - len(latencies)) / count * 100
            
            return {
                "latency_ms": avg_latency,
                "jitter_ms": jitter,
                "loss_percent": loss,
                "success": True
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _simulate_probe(self, site: str, wan_link: WANLink) -> ProbeResult:
        """Generate simulated probe result."""
        # Base values vary by link
        base_latency = 15.0 if wan_link == WANLink.WAN1 else 45.0
        base_jitter = 3.0 if wan_link == WANLink.WAN1 else 8.0
        
        # Add some randomness
        latency = base_latency + random.uniform(-5, 10)
        jitter = base_jitter + random.uniform(-1, 3)
        loss = random.uniform(0, 1.0)
        
        # Site variations
        if site == "branch-b":
            latency += 10
        if site == "branch-c":
            latency += 20
            jitter += 2
        
        return ProbeResult(
            site=site,
            wan_link=wan_link,
            probe_type=ProbeType.ICMP,
            target=DEFAULT_TARGETS.get(wan_link, "8.8.8.8"),
            latency_ms=max(1, latency),
            jitter_ms=max(0, jitter),
            loss_percent=max(0, min(100, loss)),
            bandwidth_mbps=random.uniform(50, 100),
            success=True
        )
    
    def get_history(self, site: str, wan_link: WANLink) -> List[ProbeResult]:
        """Get probe history for a link."""
        key = f"{site}:{wan_link.value}"
        return self._probe_history.get(key, [])
    
    def get_average(self, site: str, wan_link: WANLink, window: int = 10) -> Optional[ProbeResult]:
        """Get average probe result over window."""
        history = self.get_history(site, wan_link)[-window:]
        
        if not history:
            return None
        
        avg_latency = sum(p.latency_ms for p in history) / len(history)
        avg_jitter = sum(p.jitter_ms for p in history) / len(history)
        avg_loss = sum(p.loss_percent for p in history) / len(history)
        
        return ProbeResult(
            site=site,
            wan_link=wan_link,
            probe_type=ProbeType.ICMP,
            target="average",
            latency_ms=avg_latency,
            jitter_ms=avg_jitter,
            loss_percent=avg_loss,
            success=True
        )
