"""
UPO CLI - Policy Compile and Apply
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, List

import typer
import yaml

from .compiler import PolicyCompiler
from .models import Policy

app = typer.Typer(
    name="upo",
    help="Unified Policy Orchestrator - One intent policy → per-system configs"
)


def get_compiler() -> PolicyCompiler:
    """Get compiler instance."""
    return PolicyCompiler()


@app.command()
def validate(
    policy_file: Path = typer.Argument(..., help="Policy YAML file"),
    adapter: Optional[str] = typer.Option(None, "--adapter", "-a", help="Specific adapter to validate"),
):
    """Validate a policy file."""
    if not policy_file.exists():
        typer.echo(f"Error: File not found: {policy_file}", err=True)
        raise typer.Exit(1)
    
    compiler = get_compiler()
    policy = compiler.load_policy(policy_file)
    
    adapters = [adapter] if adapter else None
    results = asyncio.run(compiler.validate(policy, adapters))
    
    all_valid = True
    for name, result in results.items():
        if result.valid:
            typer.echo(f"✓ {name}: Valid")
        else:
            typer.echo(f"✗ {name}: Invalid")
            for error in result.errors:
                typer.echo(f"  - {error.field}: {error.message}")
            all_valid = False
        
        for warning in result.warnings:
            typer.echo(f"  ⚠ {warning.field}: {warning.message}")
    
    if not all_valid:
        raise typer.Exit(1)


@app.command()
def compile(
    policy_file: Path = typer.Argument(..., help="Policy YAML file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
    adapter: Optional[str] = typer.Option(None, "--adapter", "-a", help="Specific adapter"),
    format: str = typer.Option("json", "--format", "-f", help="Output format (json, yaml)"),
):
    """Compile policy to target configurations."""
    if not policy_file.exists():
        typer.echo(f"Error: File not found: {policy_file}", err=True)
        raise typer.Exit(1)
    
    compiler = get_compiler()
    policy = compiler.load_policy(policy_file)
    
    adapters = [adapter] if adapter else None
    response = asyncio.run(compiler.compile(policy, adapters))
    
    if not response.success:
        typer.echo("Compilation failed:", err=True)
        for error in response.errors:
            typer.echo(f"  - {error}", err=True)
        raise typer.Exit(1)
    
    if output:
        compiler.save_compiled(response.outputs, output)
        typer.echo(f"Compiled configs saved to: {output}")
        for out in response.outputs:
            typer.echo(f"  - {out.adapter}/")
    else:
        # Print to stdout
        for out in response.outputs:
            typer.echo(f"\n=== {out.adapter} ===")
            for config in out.configs:
                typer.echo(f"\n# {config.target} ({config.config_type})")
                typer.echo(f"# {config.description}")
                if isinstance(config.content, str):
                    typer.echo(config.content)
                else:
                    if format == "yaml":
                        typer.echo(yaml.dump(config.content, default_flow_style=False))
                    else:
                        typer.echo(json.dumps(config.content, indent=2))


@app.command()
def apply(
    policy_file: Path = typer.Argument(..., help="Policy YAML file"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target adapter (all if not specified)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show what would be done"),
):
    """Apply policy to target systems."""
    if not policy_file.exists():
        typer.echo(f"Error: File not found: {policy_file}", err=True)
        raise typer.Exit(1)
    
    compiler = get_compiler()
    policy = compiler.load_policy(policy_file)
    
    targets = [target] if target else None
    
    if dry_run:
        typer.echo("Dry run mode - no changes will be made\n")
    
    response = asyncio.run(compiler.apply(policy, targets, dry_run=dry_run))
    
    for result in response.results:
        typer.echo(f"\n=== {result.adapter} ===")
        for change in result.changes:
            icon = "→" if dry_run else "✓"
            typer.echo(f"  {icon} [{change.action}] {change.resource_type}/{change.resource_name}")
            if change.details:
                typer.echo(f"    {change.details}")
        
        if result.errors:
            for error in result.errors:
                typer.echo(f"  ✗ {error}", err=True)
    
    if not response.success:
        typer.echo("\nSome operations failed:", err=True)
        for error in response.errors:
            typer.echo(f"  - {error}", err=True)
        raise typer.Exit(1)
    
    if dry_run:
        typer.echo("\nDry run complete. Use --no-dry-run to apply changes.")
    else:
        typer.echo("\nPolicy applied successfully.")


@app.command()
def diff(
    policy_file: Path = typer.Argument(..., help="Policy YAML file"),
    adapter: Optional[str] = typer.Option(None, "--adapter", "-a", help="Specific adapter"),
):
    """Show diff between policy and current system state."""
    typer.echo("Diff not yet implemented - showing compile output instead")
    compile(policy_file, None, adapter, "json")


@app.command("adapters")
def list_adapters():
    """List available adapters."""
    compiler = get_compiler()
    adapters = compiler.list_adapters()
    
    typer.echo("Available adapters:\n")
    for adapter in adapters:
        status = "✓ enabled" if adapter.get("enabled", True) else "✗ disabled"
        typer.echo(f"  {adapter['name']}: {adapter.get('description', '')}")
        typer.echo(f"    Status: {status}")
        caps = adapter.get("capabilities", [])
        if caps:
            typer.echo(f"    Capabilities: {', '.join(caps)}")
        typer.echo()


@app.command()
def init(
    output_file: Path = typer.Argument(
        Path("policy.yaml"), 
        help="Output file for template policy"
    ),
):
    """Create a template policy file."""
    template = """# OpenSASE-Lab Intent Policy
name: my-policy
version: "1.0"
description: Example policy

# User/group definitions
users:
  - name: employees
    type: group
    attributes:
      - role: employee

# Application definitions
apps:
  - name: app1
    address: app1.ziti
    port: 80
    segment: corp
    inspection: full

# Network segments
segments:
  - name: corp
    vlan: 100
    vrf_id: 1
  
  - name: guest
    vlan: 200
    vrf_id: 2

# Egress policies
egress:
  corp:
    action: route-via-pop
    inspection: full
  
  guest:
    action: local-breakout
    inspection: none

# Access rules
access_rules:
  - name: employees-to-apps
    users: [employees]
    apps: [app1]
    action: allow
"""
    
    output_file.write_text(template)
    typer.echo(f"Created template policy: {output_file}")
    typer.echo("Edit the file and run: upo validate policy.yaml")


def main():
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
