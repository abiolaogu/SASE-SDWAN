//! Data Plane Isolation (VRF-like)

use crate::model::TenantId;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Isolation engine - enforces tenant separation
pub struct IsolationEngine {
    /// Per-tenant VRFs
    vrfs: Arc<RwLock<HashMap<TenantId, TenantVrf>>>,
    /// Tenant context validator
    validator: ContextValidator,
}

impl IsolationEngine {
    pub fn new() -> Self {
        Self {
            vrfs: Arc::new(RwLock::new(HashMap::new())),
            validator: ContextValidator::new(),
        }
    }

    /// Create VRF for tenant
    pub fn create_vrf(&self, tenant_id: TenantId, config: VrfConfig) -> Result<(), IsolationError> {
        let vrf = TenantVrf::new(tenant_id, config);
        self.vrfs.write().insert(tenant_id, vrf);
        Ok(())
    }

    /// Get VRF for tenant
    pub fn get_vrf(&self, tenant_id: &TenantId) -> Option<TenantVrf> {
        self.vrfs.read().get(tenant_id).cloned()
    }

    /// Validate packet has correct tenant context
    pub fn validate_packet(&self, tenant_id: &TenantId, packet_tag: &TenantTag) -> bool {
        self.validator.validate(tenant_id, packet_tag)
    }

    /// Tag packet with tenant ID
    pub fn tag_packet(&self, tenant_id: TenantId) -> TenantTag {
        TenantTag {
            tenant_id,
            timestamp: now(),
            hmac: self.compute_hmac(tenant_id),
        }
    }

    fn compute_hmac(&self, tenant_id: TenantId) -> [u8; 16] {
        // Simplified HMAC - in production use proper crypto
        let mut hmac = [0u8; 16];
        hmac[..16].copy_from_slice(&tenant_id.as_bytes()[..16]);
        hmac
    }

    /// Delete tenant VRF
    pub fn delete_vrf(&self, tenant_id: &TenantId) {
        self.vrfs.write().remove(tenant_id);
    }
}

impl Default for IsolationEngine {
    fn default() -> Self { Self::new() }
}

/// Per-tenant VRF
#[derive(Debug, Clone)]
pub struct TenantVrf {
    pub tenant_id: TenantId,
    pub routing_table: RoutingTable,
    pub flow_table: FlowTable,
    pub nat_pool: NatPool,
    pub wireguard_keys: WireGuardKeys,
}

impl TenantVrf {
    pub fn new(tenant_id: TenantId, config: VrfConfig) -> Self {
        Self {
            tenant_id,
            routing_table: RoutingTable::new(&config.overlay_cidr),
            flow_table: FlowTable::new(config.max_flows),
            nat_pool: NatPool::new(&config.nat_cidr),
            wireguard_keys: WireGuardKeys::generate(),
        }
    }

    /// Lookup route for destination
    pub fn lookup_route(&self, destination: &str) -> Option<&Route> {
        self.routing_table.lookup(destination)
    }

    /// Add flow
    pub fn add_flow(&mut self, flow_id: u64, flow: Flow) -> Result<(), IsolationError> {
        if self.flow_table.count() >= self.flow_table.max_flows {
            return Err(IsolationError::FlowTableFull);
        }
        self.flow_table.insert(flow_id, flow);
        Ok(())
    }
}

/// VRF configuration
#[derive(Debug, Clone)]
pub struct VrfConfig {
    pub overlay_cidr: String,
    pub nat_cidr: String,
    pub max_flows: usize,
}

/// Routing table (per tenant)
#[derive(Debug, Clone)]
pub struct RoutingTable {
    routes: Vec<Route>,
}

impl RoutingTable {
    pub fn new(default_cidr: &str) -> Self {
        Self {
            routes: vec![Route {
                destination: default_cidr.to_string(),
                next_hop: "local".to_string(),
                metric: 0,
            }],
        }
    }

    pub fn add_route(&mut self, route: Route) {
        self.routes.push(route);
    }

    pub fn lookup(&self, _destination: &str) -> Option<&Route> {
        self.routes.first()
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    pub destination: String,
    pub next_hop: String,
    pub metric: u32,
}

/// Flow table (per tenant)
#[derive(Debug, Clone)]
pub struct FlowTable {
    flows: HashMap<u64, Flow>,
    max_flows: usize,
}

impl FlowTable {
    pub fn new(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
        }
    }

    pub fn insert(&mut self, flow_id: u64, flow: Flow) {
        self.flows.insert(flow_id, flow);
    }

    pub fn get(&self, flow_id: u64) -> Option<&Flow> {
        self.flows.get(&flow_id)
    }

    pub fn count(&self) -> usize {
        self.flows.len()
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// NAT pool (per tenant)
#[derive(Debug, Clone)]
pub struct NatPool {
    cidr: String,
    next_ip: u32,
}

impl NatPool {
    pub fn new(cidr: &str) -> Self {
        Self {
            cidr: cidr.to_string(),
            next_ip: 1,
        }
    }

    pub fn allocate(&mut self) -> String {
        let ip = self.next_ip;
        self.next_ip += 1;
        format!("10.{}.{}.{}", (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF)
    }
}

/// WireGuard keys (per tenant)
#[derive(Debug, Clone)]
pub struct WireGuardKeys {
    pub public_key: String,
    private_key: String,
    pub created_at: u64,
}

impl WireGuardKeys {
    pub fn generate() -> Self {
        // Simplified - in production use proper crypto
        Self {
            public_key: format!("pk_{}", now()),
            private_key: format!("sk_{}", now()),
            created_at: now(),
        }
    }

    pub fn rotate(&mut self) {
        *self = Self::generate();
    }
}

/// Tenant tag for packet marking
#[derive(Debug, Clone)]
pub struct TenantTag {
    pub tenant_id: TenantId,
    pub timestamp: u64,
    pub hmac: [u8; 16],
}

impl TenantTag {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(self.tenant_id.as_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.hmac);
        bytes
    }
}

/// Context validator
pub struct ContextValidator {
    // Would contain validation rules
}

impl ContextValidator {
    pub fn new() -> Self { Self {} }

    pub fn validate(&self, tenant_id: &TenantId, tag: &TenantTag) -> bool {
        tag.tenant_id == *tenant_id
    }
}

impl Default for ContextValidator {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    #[error("VRF not found")]
    VrfNotFound,
    #[error("flow table full")]
    FlowTableFull,
    #[error("invalid tenant context")]
    InvalidContext,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation() {
        let engine = IsolationEngine::new();
        let tenant_a = TenantId::new_v4();
        let tenant_b = TenantId::new_v4();
        
        engine.create_vrf(tenant_a, VrfConfig {
            overlay_cidr: "10.0.0.0/8".into(),
            nat_cidr: "100.64.0.0/10".into(),
            max_flows: 1000,
        }).unwrap();

        // Tenant A tag
        let tag_a = engine.tag_packet(tenant_a);
        
        // Should validate for tenant A
        assert!(engine.validate_packet(&tenant_a, &tag_a));
        
        // Should NOT validate for tenant B
        assert!(!engine.validate_packet(&tenant_b, &tag_a));
    }
}
