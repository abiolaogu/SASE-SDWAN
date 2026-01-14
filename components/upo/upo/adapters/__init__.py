"""
UPO Adapters Package
"""

from .base import BaseAdapter
from .opnsense import OPNsenseAdapter
from .openziti import OpenZitiAdapter
from .flexiwan import FlexiWANAdapter

# Registry of available adapters
ADAPTERS = {
    "opnsense": OPNsenseAdapter,
    "openziti": OpenZitiAdapter,
    "flexiwan": FlexiWANAdapter,
}

def get_adapter(name: str, **kwargs) -> BaseAdapter:
    """Get adapter instance by name."""
    if name not in ADAPTERS:
        raise ValueError(f"Unknown adapter: {name}. Available: {list(ADAPTERS.keys())}")
    return ADAPTERS[name](**kwargs)

def list_adapters() -> list:
    """List all available adapters."""
    return [
        {
            "name": name,
            "class": cls.__name__,
            "description": cls.description if hasattr(cls, 'description') else ""
        }
        for name, cls in ADAPTERS.items()
    ]

__all__ = [
    "BaseAdapter",
    "OPNsenseAdapter", 
    "OpenZitiAdapter",
    "FlexiWANAdapter",
    "ADAPTERS",
    "get_adapter",
    "list_adapters"
]
