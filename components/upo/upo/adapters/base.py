"""
UPO Base Adapter Interface
Abstract base class for all policy adapters
"""

from abc import ABC, abstractmethod
from typing import Optional
from ..models import Policy, ValidationResult, CompiledOutput, ApplyResult


class BaseAdapter(ABC):
    """
    Base interface for policy adapters.
    
    All adapters must implement:
    - validate: Check if policy is valid for this target
    - compile: Convert policy to target-specific config
    - apply: Apply compiled config to target system
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique adapter name."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        pass
    
    @property
    def enabled(self) -> bool:
        """Whether adapter is enabled."""
        return True
    
    @property
    def capabilities(self) -> list:
        """List of adapter capabilities."""
        return ["compile", "apply"]
    
    @abstractmethod
    async def validate(self, policy: Policy) -> ValidationResult:
        """
        Validate policy for this adapter.
        
        Args:
            policy: The policy to validate
            
        Returns:
            ValidationResult with valid flag and any errors/warnings
        """
        pass
    
    @abstractmethod
    async def compile(self, policy: Policy) -> CompiledOutput:
        """
        Compile policy to target configuration.
        
        Args:
            policy: The policy to compile
            
        Returns:
            CompiledOutput with target-specific configurations
        """
        pass
    
    @abstractmethod
    async def apply(
        self, 
        compiled: CompiledOutput, 
        dry_run: bool = False
    ) -> ApplyResult:
        """
        Apply compiled configuration to target system.
        
        Args:
            compiled: The compiled configuration
            dry_run: If True, don't actually apply changes
            
        Returns:
            ApplyResult with success status and list of changes
        """
        pass
    
    async def test_connection(self) -> bool:
        """
        Test connection to target system.
        
        Returns:
            True if connection successful
        """
        return True
    
    def get_info(self) -> dict:
        """Get adapter information."""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "capabilities": self.capabilities
        }
