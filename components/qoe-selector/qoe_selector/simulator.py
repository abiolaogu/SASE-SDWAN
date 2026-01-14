"""
QoE Path Selector - Simulator
"""

import asyncio
import random
from datetime import datetime
from typing import Dict, List, Optional, Callable
from .models import (
    ProbeResult, SiteProbes, WANLink, ProbeType,
    SimulationScenario, SimulationConfig, SimulationState
)


class QoESimulator:
    """
    Simulates network conditions for demonstration.
    """
    
    def __init__(self, sites: List[str] = None):
        self.sites = sites or ["branch-a", "branch-b", "branch-c"]
        self.state = SimulationState()
        self._callbacks: List[Callable] = []
        self._scenario_params: Dict[str, dict] = {}
    
    async def start(self, config: SimulationConfig) -> SimulationState:
        """Start a simulation scenario."""
        self.state = SimulationState(
            active=True,
            scenario=config.scenario,
            elapsed_seconds=0,
            events=[]
        )
        
        self._scenario_params = self._get_scenario_params(config.scenario)
        self.state.events.append(f"Started {config.scenario.value} simulation")
        
        # Run simulation loop
        asyncio.create_task(self._simulation_loop(config))
        
        return self.state
    
    async def stop(self) -> SimulationState:
        """Stop current simulation."""
        self.state.active = False
        self.state.events.append("Simulation stopped")
        return self.state
    
    def get_simulated_probes(self) -> Dict[str, SiteProbes]:
        """Get current simulated probe results."""
        results = {}
        
        for site in self.sites:
            probes = {}
            for wan_link in WANLink:
                probe = self._generate_probe(site, wan_link)
                probes[wan_link.value] = probe
            
            results[site] = SiteProbes(site=site, probes=probes)
        
        return results
    
    def _generate_probe(self, site: str, wan_link: WANLink) -> ProbeResult:
        """Generate simulated probe based on scenario."""
        params = self._scenario_params.get(wan_link.value, {})
        
        # Base values
        base_latency = params.get("base_latency", 20.0)
        base_jitter = params.get("base_jitter", 5.0)
        base_loss = params.get("base_loss", 0.5)
        is_down = params.get("down", False)
        
        if is_down:
            return ProbeResult(
                site=site,
                wan_link=wan_link,
                probe_type=ProbeType.ICMP,
                target="simulation",
                latency_ms=0,
                jitter_ms=0,
                loss_percent=100,
                success=False,
                error="Link down (simulated)"
            )
        
        # Add variation based on scenario
        variation = params.get("variation", 0.2)
        latency = base_latency * (1 + random.uniform(-variation, variation))
        jitter = base_jitter * (1 + random.uniform(-variation, variation))
        loss = base_loss * (1 + random.uniform(-0.5, 0.5))
        
        # Site-specific adjustments
        if site == "branch-b":
            latency += 10
        elif site == "branch-c":
            latency += 20
        
        # Time-based variation for "variable" scenario
        if self.state.scenario == SimulationScenario.VARIABLE:
            elapsed = self.state.elapsed_seconds
            cycle = (elapsed % 60) / 60  # 0 to 1 over 60 seconds
            latency += 50 * abs(0.5 - cycle)  # Oscillate latency
        
        return ProbeResult(
            site=site,
            wan_link=wan_link,
            probe_type=ProbeType.ICMP,
            target="simulation",
            latency_ms=max(1, latency),
            jitter_ms=max(0, jitter),
            loss_percent=max(0, min(100, loss)),
            bandwidth_mbps=random.uniform(50, 100),
            success=True
        )
    
    def _get_scenario_params(self, scenario: SimulationScenario) -> dict:
        """Get parameters for a scenario."""
        scenarios = {
            SimulationScenario.NORMAL: {
                "wan1": {"base_latency": 15, "base_jitter": 3, "base_loss": 0.2},
                "wan2": {"base_latency": 45, "base_jitter": 8, "base_loss": 0.5}
            },
            SimulationScenario.WAN1_CONGESTION: {
                "wan1": {"base_latency": 150, "base_jitter": 50, "base_loss": 5},
                "wan2": {"base_latency": 45, "base_jitter": 8, "base_loss": 0.5}
            },
            SimulationScenario.WAN2_CONGESTION: {
                "wan1": {"base_latency": 15, "base_jitter": 3, "base_loss": 0.2},
                "wan2": {"base_latency": 200, "base_jitter": 80, "base_loss": 10}
            },
            SimulationScenario.WAN1_FAILURE: {
                "wan1": {"down": True},
                "wan2": {"base_latency": 45, "base_jitter": 8, "base_loss": 0.5}
            },
            SimulationScenario.WAN2_FAILURE: {
                "wan1": {"base_latency": 15, "base_jitter": 3, "base_loss": 0.2},
                "wan2": {"down": True}
            },
            SimulationScenario.VARIABLE: {
                "wan1": {"base_latency": 30, "base_jitter": 10, "base_loss": 1, "variation": 0.5},
                "wan2": {"base_latency": 60, "base_jitter": 15, "base_loss": 2, "variation": 0.5}
            },
            SimulationScenario.FAILOVER: {
                "wan1": {"base_latency": 15, "base_jitter": 3, "base_loss": 0.2},
                "wan2": {"base_latency": 45, "base_jitter": 8, "base_loss": 0.5}
            }
        }
        return scenarios.get(scenario, scenarios[SimulationScenario.NORMAL])
    
    async def _simulation_loop(self, config: SimulationConfig):
        """Main simulation loop."""
        while self.state.active and self.state.elapsed_seconds < config.duration_seconds:
            await asyncio.sleep(config.update_interval_seconds)
            self.state.elapsed_seconds += config.update_interval_seconds
            
            # Special handling for failover scenario
            if config.scenario == SimulationScenario.FAILOVER:
                if self.state.elapsed_seconds == 20:
                    self._scenario_params["wan1"]["down"] = True
                    self.state.events.append("WAN1 failure detected")
                elif self.state.elapsed_seconds == 40:
                    self._scenario_params["wan1"]["down"] = False
                    self.state.events.append("WAN1 recovered")
            
            # Notify callbacks
            for callback in self._callbacks:
                await callback(self.get_simulated_probes())
        
        self.state.active = False
        self.state.events.append("Simulation completed")
    
    def on_update(self, callback: Callable):
        """Register callback for simulation updates."""
        self._callbacks.append(callback)
