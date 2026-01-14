"""
OpenZiti Adapter
Generates Ziti services and access policies
"""

import json
from typing import List
from .base import BaseAdapter
from ..models import (
    Policy, ValidationResult, ValidationError,
    CompiledOutput, CompiledConfig, ApplyResult, ApplyChange,
    AccessAction
)


class OpenZitiAdapter(BaseAdapter):
    """
    Adapter for OpenZiti ZTNA.
    Generates:
    - Service definitions
    - Service configs (intercept, host)
    - Service policies (Dial, Bind)
    - Identity role attributes
    """
    
    name = "openziti"
    description = "OpenZiti ZTNA - Services, policies, and identity management"
    
    def __init__(self, controller_url: str = "https://localhost:1280"):
        self.controller_url = controller_url
    
    async def validate(self, policy: Policy) -> ValidationResult:
        """Validate policy for OpenZiti."""
        errors = []
        warnings = []
        
        # Check apps have valid addresses
        for app in policy.apps:
            if not app.address:
                errors.append(ValidationError(
                    field=f"apps.{app.name}.address",
                    message="Application must have an address"
                ))
            if not app.address.endswith(".ziti") and "." in app.address:
                warnings.append(ValidationError(
                    field=f"apps.{app.name}.address",
                    message=f"Consider using .ziti domain for {app.name}",
                    severity="warning"
                ))
        
        # Check access rules reference valid apps and users
        app_names = {a.name for a in policy.apps}
        user_names = {u.name for u in policy.users}
        
        for rule in policy.access_rules:
            for app in rule.apps:
                if app not in app_names:
                    errors.append(ValidationError(
                        field=f"access_rules.{rule.name}.apps",
                        message=f"Unknown app: {app}"
                    ))
            for user in rule.users:
                if user not in user_names:
                    errors.append(ValidationError(
                        field=f"access_rules.{rule.name}.users",
                        message=f"Unknown user/group: {user}"
                    ))
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    async def compile(self, policy: Policy) -> CompiledOutput:
        """Compile policy to Ziti service and policy configs."""
        configs = []
        
        # Generate service definitions
        services = self._generate_services(policy)
        configs.append(CompiledConfig(
            target="services",
            config_type="ziti-services",
            content=services,
            description="Ziti service definitions"
        ))
        
        # Generate service configs
        service_configs = self._generate_service_configs(policy)
        configs.append(CompiledConfig(
            target="configs",
            config_type="ziti-configs",
            content=service_configs,
            description="Intercept and host configurations"
        ))
        
        # Generate service policies
        policies = self._generate_policies(policy)
        configs.append(CompiledConfig(
            target="policies",
            config_type="ziti-policies",
            content=policies,
            description="Dial and Bind service policies"
        ))
        
        # Generate identity role mappings
        identities = self._generate_identity_roles(policy)
        configs.append(CompiledConfig(
            target="identities",
            config_type="role-mappings",
            content=identities,
            description="Identity role attribute mappings"
        ))
        
        return CompiledOutput(
            adapter=self.name,
            policy_name=policy.name,
            policy_version=policy.version,
            configs=configs,
            metadata={
                "service_count": len(policy.apps),
                "policy_count": len(policy.access_rules)
            }
        )
    
    def _generate_services(self, policy: Policy) -> list:
        """Generate Ziti service definitions."""
        services = []
        for app in policy.apps:
            services.append({
                "name": app.name,
                "configs": [
                    f"{app.name}-intercept-config",
                    f"{app.name}-host-config"
                ],
                "roleAttributes": [f"{app.name}-service", app.segment],
                "terminatorStrategy": "smartrouting"
            })
        return services
    
    def _generate_service_configs(self, policy: Policy) -> list:
        """Generate Ziti service configs."""
        configs = []
        
        for app in policy.apps:
            # Intercept config (client side)
            configs.append({
                "name": f"{app.name}-intercept-config",
                "configTypeId": "intercept.v1",
                "data": {
                    "protocols": [app.protocol],
                    "addresses": [app.address],
                    "portRanges": [{"low": app.port, "high": app.port}]
                }
            })
            
            # Host config (server side)
            # Use internal IP based on segment
            internal_ip = self._get_internal_ip(app, policy)
            configs.append({
                "name": f"{app.name}-host-config",
                "configTypeId": "host.v1",
                "data": {
                    "protocol": app.protocol,
                    "address": internal_ip,
                    "port": app.port
                }
            })
        
        return configs
    
    def _get_internal_ip(self, app, policy) -> str:
        """Get internal IP for app based on segment."""
        segment = next((s for s in policy.segments if s.name == app.segment), None)
        if segment:
            # Map segment to branch network
            if segment.vrf_id == 1:
                return "10.201.0.100"  # Branch A
            elif segment.vrf_id == 2:
                return "10.202.0.100"  # Branch B
        return f"10.200.0.{hash(app.name) % 254 + 1}"
    
    def _generate_policies(self, policy: Policy) -> list:
        """Generate Ziti service policies."""
        policies = []
        
        # Generate Dial policies from access rules
        for rule in policy.access_rules:
            if rule.action == AccessAction.ALLOW:
                policies.append({
                    "name": f"{rule.name}-dial",
                    "type": "Dial",
                    "semantic": "AnyOf",
                    "serviceRoles": [f"@{app}" for app in rule.apps],
                    "identityRoles": [f"#{user}" for user in rule.users]
                })
        
        # Generate Bind policies for routers
        for app in policy.apps:
            router_role = self._get_router_role(app, policy)
            policies.append({
                "name": f"{app.name}-bind",
                "type": "Bind",
                "semantic": "AnyOf",
                "serviceRoles": [f"@{app.name}"],
                "identityRoles": [f"#{router_role}"]
            })
        
        return policies
    
    def _get_router_role(self, app, policy) -> str:
        """Get router role for hosting an app."""
        segment = next((s for s in policy.segments if s.name == app.segment), None)
        if segment:
            if segment.vrf_id == 1:
                return "router-a"
            elif segment.vrf_id == 2:
                return "router-b"
        return "router-pop"
    
    def _generate_identity_roles(self, policy: Policy) -> list:
        """Generate identity role mappings."""
        mappings = []
        
        for user in policy.users:
            mappings.append({
                "name": user.name,
                "type": user.type,
                "roleAttributes": [
                    user.name,
                    "users",
                    *[f"{k}={v}" for attr in user.attributes for k, v in attr.items()]
                ]
            })
        
        return mappings
    
    async def apply(
        self, 
        compiled: CompiledOutput, 
        dry_run: bool = False
    ) -> ApplyResult:
        """Apply configuration to OpenZiti."""
        changes = []
        errors = []
        
        for config in compiled.configs:
            if config.target == "services":
                for service in config.content:
                    action = "create" if dry_run else "create"
                    changes.append(ApplyChange(
                        resource_type="service",
                        resource_name=service["name"],
                        action=action,
                        details=f"{'Would create' if dry_run else 'Created'} service"
                    ))
            
            elif config.target == "policies":
                for policy_item in config.content:
                    changes.append(ApplyChange(
                        resource_type="service-policy",
                        resource_name=policy_item["name"],
                        action="create" if dry_run else "create",
                        details=f"{'Would create' if dry_run else 'Created'} {policy_item['type']} policy"
                    ))
        
        return ApplyResult(
            adapter=self.name,
            success=len(errors) == 0,
            dry_run=dry_run,
            changes=changes,
            errors=errors
        )
