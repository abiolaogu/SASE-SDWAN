"""
UPO FastAPI Application
REST API for the Unified Policy Orchestrator
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pathlib import Path
from typing import Optional, List
import yaml

from .models import (
    Policy, CompileRequest, CompileResponse,
    ApplyRequest, ApplyResponse, AdapterInfo
)
from .compiler import PolicyCompiler, get_compiler

app = FastAPI(
    title="Unified Policy Orchestrator (UPO)",
    description="One intent policy → translated into per-system configs",
    version="1.0.0"
)

# Initialize compiler
compiler = get_compiler()


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "upo"}


@app.get("/api/v1/adapters", response_model=List[AdapterInfo])
async def list_adapters():
    """List all available adapters."""
    return compiler.list_adapters()


@app.post("/api/v1/policy/validate")
async def validate_policy(
    request: CompileRequest
):
    """Validate a policy against all or specified adapters."""
    results = await compiler.validate(
        request.policy, 
        request.adapters
    )
    
    # Transform to response format
    validation_results = {}
    all_valid = True
    
    for name, result in results.items():
        validation_results[name] = {
            "valid": result.valid,
            "errors": [e.dict() for e in result.errors],
            "warnings": [w.dict() for w in result.warnings]
        }
        if not result.valid:
            all_valid = False
    
    return {
        "valid": all_valid,
        "results": validation_results
    }


@app.post("/api/v1/policy/compile", response_model=CompileResponse)
async def compile_policy(request: CompileRequest):
    """Compile policy to target configurations."""
    response = await compiler.compile(
        request.policy,
        request.adapters
    )
    return response


@app.post("/api/v1/policy/apply", response_model=ApplyResponse)
async def apply_policy(request: ApplyRequest):
    """Compile and apply policy to target systems."""
    response = await compiler.apply(
        request.policy,
        request.targets,
        request.dry_run
    )
    return response


@app.get("/api/v1/policy/status")
async def policy_status():
    """Get current policy status."""
    # TODO: Track applied policies
    return {
        "current_policy": None,
        "last_applied": None,
        "adapters_status": {
            name: {
                "enabled": adapter.enabled,
                "connected": await adapter.test_connection()
            }
            for name, adapter in compiler._adapters.items()
        }
    }


@app.post("/api/v1/policy/parse")
async def parse_policy(policy_yaml: str):
    """Parse YAML policy and return structured form."""
    try:
        data = yaml.safe_load(policy_yaml)
        policy = Policy(**data)
        return {"success": True, "policy": policy.dict()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# Demo endpoint
@app.post("/api/v1/demo/full-flow")
async def demo_full_flow(
    background_tasks: BackgroundTasks,
    policy: Policy,
    dry_run: bool = True
):
    """
    Demo endpoint: Full policy flow.
    
    1. Validates policy
    2. Compiles to all targets
    3. Applies (dry run by default)
    4. Returns summary
    """
    # Validate
    validation = await compiler.validate(policy)
    
    # Compile
    compile_response = await compiler.compile(policy)
    
    # Apply
    apply_response = await compiler.apply(policy, dry_run=dry_run)
    
    return {
        "validation": {
            name: {"valid": r.valid, "errors": len(r.errors)}
            for name, r in validation.items()
        },
        "compilation": {
            "success": compile_response.success,
            "outputs": len(compile_response.outputs)
        },
        "application": {
            "success": apply_response.success,
            "dry_run": dry_run,
            "changes": sum(len(r.changes) for r in apply_response.results)
        }
    }


def run_server(host: str = "0.0.0.0", port: int = 8090):
    """Run the FastAPI server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
