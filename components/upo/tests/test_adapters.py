"""
UPO Unit Tests - Adapters
"""

import pytest
from upo.models import (
    Policy, UserGroup, Application, Segment, EgressPolicy,
    AccessRule, InspectionLevel, EgressAction, AccessAction
)
from upo.adapters import OPNsenseAdapter, OpenZitiAdapter, FlexiWANAdapter


@pytest.fixture
def sample_policy():
    """Create a sample policy for testing."""
    return Policy(
        name="test-policy",
        version="1.0",
        description="Test policy",
        users=[
            UserGroup(name="employees", type="group", attributes=[{"role": "employee"}]),
            UserGroup(name="contractors", type="group", attributes=[{"role": "contractor"}])
        ],
        apps=[
            Application(
                name="app1",
                address="app1.ziti",
                port=80,
                segment="corp",
                inspection=InspectionLevel.FULL
            ),
            Application(
                name="app2",
                address="app2.ziti",
                port=80,
                segment="corp",
                inspection=InspectionLevel.METADATA
            )
        ],
        segments=[
            Segment(name="corp", vlan=100, vrf_id=1),
            Segment(name="guest", vlan=200, vrf_id=2)
        ],
        egress={
            "corp": EgressPolicy(action=EgressAction.ROUTE_VIA_POP, inspection=InspectionLevel.FULL),
            "guest": EgressPolicy(action=EgressAction.LOCAL_BREAKOUT, inspection=InspectionLevel.NONE)
        },
        access_rules=[
            AccessRule(
                name="employees-to-apps",
                users=["employees"],
                apps=["app1", "app2"],
                action=AccessAction.ALLOW
            ),
            AccessRule(
                name="contractors-limited",
                users=["contractors"],
                apps=["app1"],
                action=AccessAction.ALLOW
            )
        ]
    )


class TestOPNsenseAdapter:
    """Tests for OPNsense adapter."""
    
    @pytest.fixture
    def adapter(self):
        return OPNsenseAdapter()
    
    @pytest.mark.asyncio
    async def test_validate_valid_policy(self, adapter, sample_policy):
        """Test validation of valid policy."""
        result = await adapter.validate(sample_policy)
        assert result.valid is True
        assert len(result.errors) == 0
    
    @pytest.mark.asyncio
    async def test_validate_invalid_vlan(self, adapter, sample_policy):
        """Test validation catches invalid VLAN."""
        sample_policy.segments[0].vlan = 5000  # Invalid
        result = await adapter.validate(sample_policy)
        assert result.valid is False
        assert any("VLAN" in e.message for e in result.errors)
    
    @pytest.mark.asyncio
    async def test_compile_generates_nftables(self, adapter, sample_policy):
        """Test compilation generates nftables rules."""
        output = await adapter.compile(sample_policy)
        
        assert output.adapter == "opnsense"
        assert output.policy_name == "test-policy"
        
        nft_config = next(c for c in output.configs if c.target == "nftables")
        assert "table inet filter" in nft_config.content
        assert "segment_corp" in nft_config.content
    
    @pytest.mark.asyncio
    async def test_compile_generates_suricata_config(self, adapter, sample_policy):
        """Test compilation generates Suricata config."""
        output = await adapter.compile(sample_policy)
        
        suricata_config = next(c for c in output.configs if c.target == "suricata")
        assert suricata_config.content["policy_name"] == "test-policy"
        assert "corp" in suricata_config.content["segments"]
    
    @pytest.mark.asyncio
    async def test_apply_dry_run(self, adapter, sample_policy):
        """Test apply in dry-run mode."""
        output = await adapter.compile(sample_policy)
        result = await adapter.apply(output, dry_run=True)
        
        assert result.dry_run is True
        assert len(result.changes) > 0
        assert all("Would" in c.details for c in result.changes)


class TestOpenZitiAdapter:
    """Tests for OpenZiti adapter."""
    
    @pytest.fixture
    def adapter(self):
        return OpenZitiAdapter()
    
    @pytest.mark.asyncio
    async def test_validate_valid_policy(self, adapter, sample_policy):
        """Test validation of valid policy."""
        result = await adapter.validate(sample_policy)
        assert result.valid is True
    
    @pytest.mark.asyncio
    async def test_validate_unknown_app_in_rule(self, adapter, sample_policy):
        """Test validation catches unknown app reference."""
        sample_policy.access_rules[0].apps.append("unknown-app")
        result = await adapter.validate(sample_policy)
        assert result.valid is False
        assert any("Unknown app" in e.message for e in result.errors)
    
    @pytest.mark.asyncio
    async def test_compile_generates_services(self, adapter, sample_policy):
        """Test compilation generates Ziti services."""
        output = await adapter.compile(sample_policy)
        
        services_config = next(c for c in output.configs if c.target == "services")
        assert len(services_config.content) == 2  # app1, app2
        assert any(s["name"] == "app1" for s in services_config.content)
    
    @pytest.mark.asyncio
    async def test_compile_generates_policies(self, adapter, sample_policy):
        """Test compilation generates Ziti policies."""
        output = await adapter.compile(sample_policy)
        
        policies_config = next(c for c in output.configs if c.target == "policies")
        dial_policies = [p for p in policies_config.content if p["type"] == "Dial"]
        bind_policies = [p for p in policies_config.content if p["type"] == "Bind"]
        
        assert len(dial_policies) == 2  # employees-to-apps, contractors-limited
        assert len(bind_policies) == 2  # app1-bind, app2-bind


class TestFlexiWANAdapter:
    """Tests for FlexiWAN adapter."""
    
    @pytest.fixture
    def adapter(self):
        return FlexiWANAdapter()
    
    @pytest.mark.asyncio
    async def test_validate_valid_policy(self, adapter, sample_policy):
        """Test validation of valid policy."""
        result = await adapter.validate(sample_policy)
        assert result.valid is True
        # Should have warning about API limitations
        assert len(result.warnings) > 0
    
    @pytest.mark.asyncio
    async def test_compile_generates_segments(self, adapter, sample_policy):
        """Test compilation generates FlexiWAN segments."""
        output = await adapter.compile(sample_policy)
        
        segments_config = next(c for c in output.configs if c.target == "segments")
        assert len(segments_config.content) == 2
        assert any(s["name"] == "corp" for s in segments_config.content)
    
    @pytest.mark.asyncio
    async def test_compile_generates_routing(self, adapter, sample_policy):
        """Test compilation generates routing policies."""
        output = await adapter.compile(sample_policy)
        
        routing_config = next(c for c in output.configs if c.target == "routing")
        assert len(routing_config.content) == 2
        
        corp_routing = next(r for r in routing_config.content if r["matchSegment"] == "corp")
        assert corp_routing["action"] == "route-to-hub"
    
    @pytest.mark.asyncio
    async def test_compile_generates_site_template(self, adapter, sample_policy):
        """Test compilation generates site template."""
        output = await adapter.compile(sample_policy)
        
        template_config = next(c for c in output.configs if c.target == "template")
        assert template_config.content["name"] == "test-policy-site-template"
        assert len(template_config.content["interfaces"]["lan"]["vlans"]) == 2
