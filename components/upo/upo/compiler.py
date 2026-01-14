"""
UPO Policy Compiler
Central compiler that orchestrates all adapters
"""

import yaml
import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from .models import (
    Policy, ValidationResult, ValidationError,
    CompiledOutput, ApplyResult, CompileResponse, ApplyResponse
)
from .adapters import ADAPTERS, get_adapter, list_adapters


class PolicyCompiler:
    """
    Central policy compiler that coordinates all adapters.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._adapters = {}
        self._initialize_adapters()
    
    def _initialize_adapters(self):
        """Initialize all configured adapters."""
        for name, adapter_cls in ADAPTERS.items():
            adapter_config = self.config.get(name, {})
            self._adapters[name] = adapter_cls(**adapter_config)
    
    def get_adapter(self, name: str):
        """Get an adapter by name."""
        if name not in self._adapters:
            raise ValueError(f"Unknown adapter: {name}")
        return self._adapters[name]
    
    def list_adapters(self) -> list:
        """List all available adapters."""
        return [
            adapter.get_info()
            for adapter in self._adapters.values()
        ]
    
    @staticmethod
    def load_policy(source: str | Path | dict) -> Policy:
        """
        Load policy from YAML file, string, or dict.
        """
        if isinstance(source, dict):
            return Policy(**source)
        
        if isinstance(source, Path) or (isinstance(source, str) and Path(source).exists()):
            path = Path(source)
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            return Policy(**data)
        
        # Assume YAML string
        data = yaml.safe_load(source)
        return Policy(**data)
    
    async def validate(
        self, 
        policy: Policy, 
        adapters: Optional[List[str]] = None
    ) -> Dict[str, ValidationResult]:
        """
        Validate policy against all or specified adapters.
        
        Returns:
            Dict mapping adapter name to validation result
        """
        target_adapters = adapters or list(self._adapters.keys())
        results = {}
        
        for name in target_adapters:
            if name not in self._adapters:
                continue
            adapter = self._adapters[name]
            results[name] = await adapter.validate(policy)
        
        return results
    
    async def compile(
        self, 
        policy: Policy, 
        adapters: Optional[List[str]] = None
    ) -> CompileResponse:
        """
        Compile policy to target configurations.
        
        Returns:
            CompileResponse with outputs for each adapter
        """
        target_adapters = adapters or list(self._adapters.keys())
        outputs = []
        errors = []
        
        for name in target_adapters:
            if name not in self._adapters:
                errors.append(f"Unknown adapter: {name}")
                continue
            
            adapter = self._adapters[name]
            
            # Validate first
            validation = await adapter.validate(policy)
            if not validation.valid:
                errors.extend([
                    f"{name}: {e.message}" for e in validation.errors
                ])
                continue
            
            # Compile
            try:
                output = await adapter.compile(policy)
                outputs.append(output)
            except Exception as e:
                errors.append(f"{name}: {str(e)}")
        
        return CompileResponse(
            success=len(errors) == 0,
            outputs=outputs,
            errors=errors
        )
    
    async def apply(
        self, 
        policy: Policy, 
        targets: Optional[List[str]] = None,
        dry_run: bool = False
    ) -> ApplyResponse:
        """
        Compile and apply policy to target systems.
        
        Returns:
            ApplyResponse with results for each adapter
        """
        # First compile
        compile_response = await self.compile(policy, targets)
        
        if not compile_response.success:
            return ApplyResponse(
                success=False,
                results=[],
                errors=compile_response.errors
            )
        
        # Then apply each compiled output
        results = []
        errors = []
        
        for output in compile_response.outputs:
            adapter_name = output.adapter
            if adapter_name not in self._adapters:
                continue
            
            adapter = self._adapters[adapter_name]
            
            try:
                result = await adapter.apply(output, dry_run=dry_run)
                results.append(result)
                if not result.success:
                    errors.extend(result.errors)
            except Exception as e:
                errors.append(f"{adapter_name}: {str(e)}")
        
        return ApplyResponse(
            success=len(errors) == 0,
            results=results,
            errors=errors
        )
    
    def save_compiled(
        self, 
        outputs: List[CompiledOutput], 
        output_dir: Path
    ):
        """Save compiled outputs to directory."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for output in outputs:
            adapter_dir = output_dir / output.adapter
            adapter_dir.mkdir(exist_ok=True)
            
            # Save each config
            for config in output.configs:
                filename = f"{config.target}.{self._get_extension(config.config_type)}"
                filepath = adapter_dir / filename
                
                if isinstance(config.content, str):
                    filepath.write_text(config.content)
                else:
                    filepath.write_text(json.dumps(config.content, indent=2))
            
            # Save metadata
            metadata_path = adapter_dir / "metadata.json"
            metadata_path.write_text(json.dumps({
                "policy_name": output.policy_name,
                "policy_version": output.policy_version,
                "adapter": output.adapter,
                "metadata": output.metadata
            }, indent=2))
    
    def _get_extension(self, config_type: str) -> str:
        """Get file extension for config type."""
        if "nft" in config_type or "rules" in config_type:
            return "nft"
        elif "yaml" in config_type:
            return "yaml"
        return "json"


# Global compiler instance
_compiler: Optional[PolicyCompiler] = None

def get_compiler(config: Optional[dict] = None) -> PolicyCompiler:
    """Get or create global compiler instance."""
    global _compiler
    if _compiler is None:
        _compiler = PolicyCompiler(config)
    return _compiler
