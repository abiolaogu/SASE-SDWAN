# Unified Policy Orchestrator (UPO)

One intent policy → translated into per-system configs.

## Overview

The UPO translates high-level YAML intent policies into concrete configurations for:
- **OPNsense/Security PoP**: Firewall rules, Suricata toggles
- **OpenZiti**: Services and access policies
- **FlexiWAN**: Site templates and routing intents

## Requirements

### Functional
- Parse YAML intent policies with users, apps, segments, egress rules, inspection levels
- Plugin architecture with adapter interfaces for each target system
- CLI with `compile`, `apply`, `validate` commands
- Generate human-readable diff of changes

### Non-Goals
- Real-time policy synchronization (batch mode only)
- Full policy conflict resolution
- Policy versioning/rollback (future enhancement)
- GUI interface

## Quick Start

```bash
# Install
pip install -e components/upo

# Validate policy
upo validate sample_policies/corporate-access.yaml

# Compile to target configs
upo compile sample_policies/corporate-access.yaml --output /tmp/configs

# Apply to running systems
upo apply sample_policies/corporate-access.yaml --target all

# Dry-run mode
upo apply sample_policies/corporate-access.yaml --dry-run
```

## Policy Schema

```yaml
name: corporate-access
version: "1.0"
description: Corporate network access policy

# User/group definitions
users:
  - name: employees
    type: group
    attributes:
      - role: employee
  - name: contractors
    type: group
    attributes:
      - role: contractor

# Application definitions
apps:
  - name: app1
    address: app1.ziti
    port: 80
    segment: corp
    inspection: full       # full, metadata, none
    
  - name: app2
    address: app2.ziti
    port: 80
    segment: corp
    inspection: metadata

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
    action: route-via-pop   # Inspect at Security PoP
    inspection: full
    
  guest:
    action: local-breakout  # Direct internet access
    inspection: none

# Access rules
access_rules:
  - name: employees-to-corp-apps
    users: [employees]
    apps: [app1, app2]
    action: allow
    
  - name: contractors-limited
    users: [contractors]
    apps: [app1]
    action: allow
    conditions:
      time_window: business_hours
```

## API Reference

### REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/policy/validate` | POST | Validate policy YAML |
| `/api/v1/policy/compile` | POST | Compile to target configs |
| `/api/v1/policy/apply` | POST | Apply to running systems |
| `/api/v1/policy/status` | GET | Current policy status |
| `/api/v1/adapters` | GET | List available adapters |
| `/health` | GET | Health check |

### CLI Commands

```bash
# Validate
upo validate <policy.yaml>

# Compile
upo compile <policy.yaml> [--output DIR] [--adapter NAME]

# Apply
upo apply <policy.yaml> [--target all|opnsense|ziti|flexiwan] [--dry-run]

# Show diff
upo diff <policy.yaml>

# List adapters
upo adapters list
```

## Adapter Interface

All adapters implement the `BaseAdapter` interface:

```python
class BaseAdapter(ABC):
    """Base interface for policy adapters."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter name."""
        pass
    
    @abstractmethod
    async def validate(self, policy: Policy) -> ValidationResult:
        """Validate policy for this adapter."""
        pass
    
    @abstractmethod
    async def compile(self, policy: Policy) -> CompiledOutput:
        """Compile policy to target config."""
        pass
    
    @abstractmethod
    async def apply(self, compiled: CompiledOutput, dry_run: bool = False) -> ApplyResult:
        """Apply compiled config to target system."""
        pass
```

## Adding New Adapters

1. Create adapter file in `upo/adapters/`
2. Implement `BaseAdapter` interface
3. Register in `upo/adapters/__init__.py`
4. Add tests in `tests/test_adapters/`

Example:
```python
# upo/adapters/my_adapter.py
from .base import BaseAdapter

class MyAdapter(BaseAdapter):
    name = "my-system"
    
    async def validate(self, policy):
        # Validation logic
        pass
    
    async def compile(self, policy):
        # Compilation logic
        pass
    
    async def apply(self, compiled, dry_run=False):
        # Application logic
        pass
```

## Testing

```bash
# Run all tests
pytest components/upo/tests/

# Run specific adapter tests
pytest components/upo/tests/test_adapters/

# With coverage
pytest --cov=upo components/upo/tests/
```

## Limitations

- Batch mode only (no real-time sync)
- FlexiWAN adapter limited by OSS API availability
- No automatic conflict resolution
- No policy versioning
