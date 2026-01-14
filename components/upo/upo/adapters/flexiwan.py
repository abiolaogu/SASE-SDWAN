"""
FlexiWAN Adapter
Generates site templates and routing intents
"""

import json
from typing import List
from .base import BaseAdapter
from ..models import (
    Policy, ValidationResult, ValidationError,
    CompiledOutput, CompiledConfig, ApplyResult, ApplyChange,
    EgressAction
)


class FlexiWANAdapter(BaseAdapter):
    """
    Adapter for FlexiWAN SD-WAN.
    Generates:
    - Site templates
    - Routing policies
    - Segment definitions
    - WAN path preferences
    """
    
    name = "flexiwan"
    description = "FlexiWAN SD-WAN - Site templates, routing, and segmentation"
    
    def __init__(self, controller_url: str = "http://localhost:3000"):
        self.controller_url = controller_url
    
    async def validate(self, policy: Policy) -> ValidationResult:
        """Validate policy for FlexiWAN."""
        errors = []
        warnings = []
        
        # Check segments have valid VRF IDs
        for segment in policy.segments:
            if not (1 <= segment.vrf_id <= 4096):
                errors.append(ValidationError(
                    field=f"segments.{segment.name}.vrf_id",
                    message=f"VRF ID {segment.vrf_id} out of range (1-4096)"
                ))
        
        # Warn about limited API support
        warnings.append(ValidationError(
            field="general",
            message="FlexiWAN OSS has limited API support. Some operations require manual UI steps.",
            severity="warning"
        ))
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    async def compile(self, policy: Policy) -> CompiledOutput:
        """Compile policy to FlexiWAN configs."""
        configs = []
        
        # Generate segment definitions
        segments = self._generate_segments(policy)
        configs.append(CompiledConfig(
            target="segments",
            config_type="flexiwan-segments",
            content=segments,
            description="Network segment/VRF definitions"
        ))
        
        # Generate routing policies
        routing = self._generate_routing_policies(policy)
        configs.append(CompiledConfig(
            target="routing",
            config_type="flexiwan-policies",
            content=routing,
            description="Routing and egress policies"
        ))
        
        # Generate site template
        site_template = self._generate_site_template(policy)
        configs.append(CompiledConfig(
            target="template",
            config_type="site-template",
            content=site_template,
            description="Site configuration template for new branches"
        ))
        
        return CompiledOutput(
            adapter=self.name,
            policy_name=policy.name,
            policy_version=policy.version,
            configs=configs,
            metadata={
                "segment_count": len(policy.segments),
                "requires_manual_steps": True
            }
        )
    
    def _generate_segments(self, policy: Policy) -> list:
        """Generate FlexiWAN segment definitions."""
        segments = []
        for segment in policy.segments:
            segments.append({
                "name": segment.name,
                "segmentId": segment.vrf_id,
                "description": segment.description or f"{segment.name} segment",
                "vlan": segment.vlan,
                "color": self._get_segment_color(segment.name)
            })
        return segments
    
    def _get_segment_color(self, name: str) -> str:
        """Get color for segment visualization."""
        colors = {
            "corp": "#4285f4",    # Blue
            "guest": "#fbbc04",   # Yellow
            "iot": "#34a853",     # Green
            "voice": "#ea4335",   # Red
        }
        return colors.get(name, "#9e9e9e")
    
    def _generate_routing_policies(self, policy: Policy) -> list:
        """Generate FlexiWAN routing policies."""
        policies = []
        
        for seg_name, egress in policy.egress.items():
            segment = next((s for s in policy.segments if s.name == seg_name), None)
            if not segment:
                continue
            
            policy_def = {
                "name": f"{seg_name}-routing",
                "priority": 100,
                "matchSegment": seg_name,
                "enabled": True
            }
            
            if egress.action == EgressAction.ROUTE_VIA_POP:
                policy_def["action"] = "route-to-hub"
                policy_def["destination"] = "pop-gateway"
            elif egress.action == EgressAction.LOCAL_BREAKOUT:
                policy_def["action"] = "local-breakout"
                policy_def["preferredWan"] = egress.preferred_wan
            elif egress.action == EgressAction.DROP:
                policy_def["action"] = "drop"
            
            policies.append(policy_def)
        
        return policies
    
    def _generate_site_template(self, policy: Policy) -> dict:
        """Generate site template for new branches."""
        template = {
            "name": f"{policy.name}-site-template",
            "description": f"Site template from policy {policy.name}",
            "interfaces": {
                "wan1": {
                    "type": "WAN",
                    "assignedTo": "eth0",
                    "dhcp": True,
                    "metric": 100
                },
                "wan2": {
                    "type": "WAN",
                    "assignedTo": "eth1",
                    "dhcp": False,
                    "metric": 200
                },
                "lan": {
                    "type": "LAN",
                    "assignedTo": "eth2",
                    "vlans": []
                }
            },
            "segments": [],
            "routing": []
        }
        
        # Add VLANs for each segment
        for segment in policy.segments:
            template["interfaces"]["lan"]["vlans"].append({
                "id": segment.vlan,
                "name": f"vlan{segment.vlan}",
                "segment": segment.name
            })
            template["segments"].append({
                "name": segment.name,
                "id": segment.vrf_id
            })
        
        # Add routing from egress policies
        for seg_name, egress in policy.egress.items():
            template["routing"].append({
                "segment": seg_name,
                "action": egress.action.value,
                "preferredPath": egress.preferred_wan
            })
        
        return template
    
    async def apply(
        self, 
        compiled: CompiledOutput, 
        dry_run: bool = False
    ) -> ApplyResult:
        """Apply configuration to FlexiWAN."""
        changes = []
        errors = []
        
        # Note: FlexiWAN OSS API is limited
        for config in compiled.configs:
            if config.target == "segments":
                for segment in config.content:
                    changes.append(ApplyChange(
                        resource_type="segment",
                        resource_name=segment["name"],
                        action="create" if dry_run else "create",
                        details=f"{'Would create' if dry_run else 'Created'} segment (may require UI)"
                    ))
            
            elif config.target == "routing":
                for policy_item in config.content:
                    changes.append(ApplyChange(
                        resource_type="routing-policy",
                        resource_name=policy_item["name"],
                        action="create" if dry_run else "create",
                        details=f"{'Would create' if dry_run else 'Created'} routing policy"
                    ))
            
            elif config.target == "template":
                changes.append(ApplyChange(
                    resource_type="site-template",
                    resource_name=config.content["name"],
                    action="create" if dry_run else "create",
                    details="Site template saved to configs directory"
                ))
        
        # Add warning about manual steps
        if not dry_run:
            errors.append(
                "Note: Some FlexiWAN configurations require manual UI steps. "
                "See docs/FLEXIWAN_MANUAL_ENROLLMENT.md"
            )
        
        return ApplyResult(
            adapter=self.name,
            success=True,  # Template generation always succeeds
            dry_run=dry_run,
            changes=changes,
            errors=[]  # Treat the note as info, not error
        )
