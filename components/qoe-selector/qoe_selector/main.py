"""
QoE Path Selector - FastAPI Application
"""

from fastapi import FastAPI
from typing import List, Optional
from datetime import datetime

from .models import (
    AppClass, WANLink, SimulationConfig, SimulationScenario,
    ProbeRequest, ScoreRequest, SimulateRequest
)
from .probes import ProbeCollector
from .scorer import PathScorer
from .recommender import SteeringRecommender
from .simulator import QoESimulator

app = FastAPI(
    title="QoE Path Selector",
    description="SD-WAN path selection based on Quality of Experience metrics",
    version="1.0.0"
)

# Initialize components
collector = ProbeCollector()
scorer = PathScorer()
recommender = SteeringRecommender(scorer)
simulator = QoESimulator()


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "qoe-selector",
        "simulation_active": simulator.state.active
    }


@app.get("/api/v1/probes")
async def get_probes(site: Optional[str] = None):
    """Get current probe results."""
    if simulator.state.active:
        probes = simulator.get_simulated_probes()
    else:
        probes = await collector.collect_all()
    
    if site:
        return {site: probes.get(site)}
    
    return {
        site: {
            wan: probe.dict()
            for wan, probe in site_probes.probes.items()
        }
        for site, site_probes in probes.items()
    }


@app.get("/api/v1/probes/{site}")
async def get_site_probes(site: str):
    """Get probes for a specific site."""
    if simulator.state.active:
        probes = simulator.get_simulated_probes()
    else:
        probes = await collector.collect_all()
    
    if site not in probes:
        return {"error": f"Unknown site: {site}"}
    
    return probes[site].dict()


@app.get("/api/v1/scores")
async def get_scores(
    site: Optional[str] = None,
    app_class: Optional[AppClass] = None
):
    """Get computed path scores."""
    if simulator.state.active:
        probes = simulator.get_simulated_probes()
    else:
        probes = await collector.collect_all()
    
    app_classes = [app_class] if app_class else None
    scores = scorer.score_all(probes, app_classes)
    
    if site:
        return {site: scores.get(site, {})}
    
    # Convert to serializable format
    result = {}
    for s, class_scores in scores.items():
        result[s] = {}
        for cls, wan_scores in class_scores.items():
            result[s][cls] = {
                wan: score.dict() 
                for wan, score in wan_scores.items()
            }
    
    return result


@app.get("/api/v1/recommendations")
async def get_recommendations(
    site: Optional[str] = None,
    app_class: Optional[AppClass] = None
):
    """Get steering recommendations."""
    if simulator.state.active:
        probes = simulator.get_simulated_probes()
    else:
        probes = await collector.collect_all()
    
    if site:
        probes = {site: probes[site]} if site in probes else {}
    
    app_classes = [app_class] if app_class else None
    rec_set = recommender.recommend_all(probes, app_classes)
    
    return rec_set.dict()


@app.get("/api/v1/recommendations/{site}/{app_class}")
async def get_site_recommendation(site: str, app_class: AppClass):
    """Get recommendation for specific site and app class."""
    if simulator.state.active:
        probes = simulator.get_simulated_probes()
    else:
        probes = await collector.collect_all()
    
    if site not in probes:
        return {"error": f"Unknown site: {site}"}
    
    rec = recommender.recommend(probes[site], app_class)
    return rec.dict()


@app.post("/api/v1/simulate")
async def start_simulation(request: SimulateRequest):
    """Start a simulation scenario."""
    state = await simulator.start(request.config)
    return {
        "message": f"Started {request.config.scenario.value} simulation",
        "state": state.dict()
    }


@app.post("/api/v1/simulate/stop")
async def stop_simulation():
    """Stop current simulation."""
    state = await simulator.stop()
    return {
        "message": "Simulation stopped",
        "state": state.dict()
    }


@app.get("/api/v1/simulate/state")
async def get_simulation_state():
    """Get current simulation state."""
    return simulator.state.dict()


@app.get("/api/v1/scenarios")
async def list_scenarios():
    """List available simulation scenarios."""
    return {
        "scenarios": [
            {"name": s.value, "description": _scenario_descriptions.get(s.value, "")}
            for s in SimulationScenario
        ]
    }


@app.get("/api/v1/app-classes")
async def list_app_classes():
    """List available app classes and their thresholds."""
    from .scorer import APP_CLASS_THRESHOLDS
    
    return {
        app_class.value: {
            "max_latency_ms": thresholds.max_latency_ms,
            "max_jitter_ms": thresholds.max_jitter_ms,
            "max_loss_percent": thresholds.max_loss_percent,
            "weights": {
                "latency": thresholds.weight_latency,
                "jitter": thresholds.weight_jitter,
                "loss": thresholds.weight_loss,
                "bandwidth": thresholds.weight_bandwidth
            }
        }
        for app_class, thresholds in APP_CLASS_THRESHOLDS.items()
    }


_scenario_descriptions = {
    "normal": "Normal operation with typical WAN latencies",
    "wan1-congestion": "WAN1 experiences high latency and packet loss",
    "wan2-congestion": "WAN2 experiences high latency and packet loss",
    "wan1-failure": "WAN1 is completely down",
    "wan2-failure": "WAN2 is completely down",
    "variable": "Network quality varies over time",
    "failover": "Simulates WAN1 failure and recovery"
}


def run_server(host: str = "0.0.0.0", port: int = 8091):
    """Run the FastAPI server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
