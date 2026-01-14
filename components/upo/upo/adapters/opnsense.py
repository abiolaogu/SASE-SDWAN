"""
OPNsense/Security PoP Adapter
Generates nftables rules and Suricata configurations
"""

import json
from typing import List
from .base import BaseAdapter
from ..models import (
    Policy, ValidationResult, ValidationError,
    CompiledOutput, CompiledConfig, ApplyResult, ApplyChange,
    InspectionLevel, EgressAction
)


class OPNsenseAdapter(BaseAdapter):
    """
    Adapter for OPNsense/Security PoP.
    Generates:
    - nftables firewall rules
    - Suricata IPS rule toggles
    - Unbound DNS blocklists
    """
    
    name = "opnsense"
    description = "Security PoP (OPNsense substitute) - Firewall, IPS, DNS"
    
    def __init__(self, api_url: str = "http://localhost:8081"):
        self.api_url = api_url
    
    async def validate(self, policy: Policy) -> ValidationResult:
        """Validate policy for Security PoP."""
        errors = []
        warnings = []
        
        # Check segments have valid VLANs
        for segment in policy.segments:
            if not (1 <= segment.vlan <= 4094):
                errors.append(ValidationError(
                    field=f"segments.{segment.name}.vlan",
                    message=f"VLAN {segment.vlan} out of range (1-4094)"
                ))
        
        # Check egress policies reference valid segments
        for seg_name in policy.egress.keys():
            if not any(s.name == seg_name for s in policy.segments):
                errors.append(ValidationError(
                    field=f"egress.{seg_name}",
                    message=f"Egress policy references unknown segment: {seg_name}"
                ))
        
        # Warn if no inspection enabled
        has_inspection = any(
            e.inspection != InspectionLevel.NONE 
            for e in policy.egress.values()
        )
        if not has_inspection:
            warnings.append(ValidationError(
                field="egress",
                message="No traffic inspection enabled",
                severity="warning"
            ))
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    async def compile(self, policy: Policy) -> CompiledOutput:
        """Compile policy to nftables and Suricata configs."""
        configs = []
        
        # Generate nftables rules
        nft_rules = self._generate_nftables(policy)
        configs.append(CompiledConfig(
            target="nftables",
            config_type="ruleset",
            content=nft_rules,
            description="Firewall rules for policy enforcement"
        ))
        
        # Generate Suricata settings
        suricata_config = self._generate_suricata_config(policy)
        configs.append(CompiledConfig(
            target="suricata",
            config_type="settings",
            content=suricata_config,
            description="IPS inspection settings per segment"
        ))
        
        # Generate segment VLAN config
        vlan_config = self._generate_vlan_config(policy)
        configs.append(CompiledConfig(
            target="vlans",
            config_type="interfaces",
            content=vlan_config,
            description="VLAN interface configuration"
        ))
        
        return CompiledOutput(
            adapter=self.name,
            policy_name=policy.name,
            policy_version=policy.version,
            configs=configs,
            metadata={"segments": [s.name for s in policy.segments]}
        )
    
    def _generate_nftables(self, policy: Policy) -> str:
        """Generate nftables ruleset."""
        rules = [
            "#!/usr/sbin/nft -f",
            f"# Generated from policy: {policy.name} v{policy.version}",
            "",
            "table inet filter {",
            "    # Policy-generated chains",
        ]
        
        # Chain for each segment
        for segment in policy.segments:
            egress = policy.egress.get(segment.name)
            rules.append(f"")
            rules.append(f"    # Segment: {segment.name} (VLAN {segment.vlan})")
            rules.append(f"    chain segment_{segment.name} {{")
            
            if egress:
                if egress.action == EgressAction.ROUTE_VIA_POP:
                    rules.append(f"        # Route via PoP for inspection")
                    rules.append(f"        mark set 0x{segment.vrf_id:02x}")
                elif egress.action == EgressAction.LOCAL_BREAKOUT:
                    rules.append(f"        # Local breakout - direct egress")
                    rules.append(f"        accept")
                elif egress.action == EgressAction.DROP:
                    rules.append(f"        # Drop all traffic")
                    rules.append(f"        drop")
            
            rules.append(f"    }}")
        
        # Access rules
        rules.append("")
        rules.append("    # Access rules from policy")
        rules.append("    chain access_policy {")
        
        for rule in policy.access_rules:
            action = "accept" if rule.action.value == "allow" else "drop"
            for app in rule.apps:
                app_def = next((a for a in policy.apps if a.name == app), None)
                if app_def:
                    rules.append(f"        # {rule.name}: {app}")
                    rules.append(f"        tcp dport {app_def.port} {action}")
        
        rules.append("    }")
        rules.append("}")
        
        return "\n".join(rules)
    
    def _generate_suricata_config(self, policy: Policy) -> dict:
        """Generate Suricata inspection settings."""
        settings = {
            "policy_name": policy.name,
            "segments": {}
        }
        
        for segment in policy.segments:
            egress = policy.egress.get(segment.name)
            if egress:
                settings["segments"][segment.name] = {
                    "vlan": segment.vlan,
                    "inspection": egress.inspection.value,
                    "ips_mode": "inline" if egress.inspection == InspectionLevel.FULL else "ids"
                }
        
        # Per-app inspection
        settings["apps"] = {}
        for app in policy.apps:
            settings["apps"][app.name] = {
                "port": app.port,
                "inspection": app.inspection.value
            }
        
        return settings
    
    def _generate_vlan_config(self, policy: Policy) -> list:
        """Generate VLAN configuration."""
        vlans = []
        for segment in policy.segments:
            vlans.append({
                "name": segment.name,
                "vlan_id": segment.vlan,
                "vrf_id": segment.vrf_id,
                "interface": f"eth2.{segment.vlan}"
            })
        return vlans
    
    async def apply(
        self, 
        compiled: CompiledOutput, 
        dry_run: bool = False
    ) -> ApplyResult:
        """Apply configuration to Security PoP."""
        changes = []
        errors = []
        
        for config in compiled.configs:
            if config.target == "nftables":
                if dry_run:
                    changes.append(ApplyChange(
                        resource_type="nftables",
                        resource_name="filter",
                        action="update",
                        details="Would update firewall rules"
                    ))
                else:
                    # TODO: Apply via API
                    changes.append(ApplyChange(
                        resource_type="nftables",
                        resource_name="filter",
                        action="update",
                        details="Updated firewall rules"
                    ))
            
            elif config.target == "suricata":
                if dry_run:
                    changes.append(ApplyChange(
                        resource_type="suricata",
                        resource_name="settings",
                        action="update",
                        details="Would update IPS settings"
                    ))
                else:
                    changes.append(ApplyChange(
                        resource_type="suricata",
                        resource_name="settings",
                        action="update",
                        details="Updated IPS settings"
                    ))
        
        return ApplyResult(
            adapter=self.name,
            success=len(errors) == 0,
            dry_run=dry_run,
            changes=changes,
            errors=errors
        )
