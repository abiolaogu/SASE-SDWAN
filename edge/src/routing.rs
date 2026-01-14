//! Routing Engine

use crate::EdgeError;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Routing engine
pub struct RoutingEngine {
    /// Routing table
    routes: Arc<RwLock<Vec<Route>>>,
    /// VRFs
    vrfs: Arc<RwLock<HashMap<String, Vrf>>>,
    /// NAT rules
    nat_rules: Arc<RwLock<Vec<NatRule>>>,
    /// BGP config
    bgp: Arc<RwLock<Option<BgpConfig>>>,
    /// OSPF config
    ospf: Arc<RwLock<Option<OspfConfig>>>,
}

impl RoutingEngine {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(Vec::new())),
            vrfs: Arc::new(RwLock::new(HashMap::new())),
            nat_rules: Arc::new(RwLock::new(Vec::new())),
            bgp: Arc::new(RwLock::new(None)),
            ospf: Arc::new(RwLock::new(None)),
        }
    }

    /// Add static route
    pub fn add_route(&self, route: Route) -> Result<(), EdgeError> {
        tracing::info!("Adding route: {} via {}", route.destination, route.next_hop);
        self.routes.write().push(route);
        self.apply_routes()?;
        Ok(())
    }

    /// Remove route
    pub fn remove_route(&self, destination: &str) -> Result<(), EdgeError> {
        self.routes.write().retain(|r| r.destination != destination);
        self.apply_routes()?;
        Ok(())
    }

    /// Add policy route
    pub fn add_policy_route(&self, policy: PolicyRoute) -> Result<(), EdgeError> {
        tracing::info!("Adding policy route for {}", policy.match_criteria);
        // ip rule add from <src> lookup <table>
        Ok(())
    }

    /// Configure SNAT
    pub fn add_snat(&self, rule: NatRule) -> Result<(), EdgeError> {
        tracing::info!("Adding SNAT: {} -> {}", rule.source, rule.translated);
        self.nat_rules.write().push(rule);
        self.apply_nat()?;
        Ok(())
    }

    /// Configure DNAT
    pub fn add_dnat(&self, rule: NatRule) -> Result<(), EdgeError> {
        tracing::info!("Adding DNAT: {} -> {}", rule.source, rule.translated);
        self.nat_rules.write().push(rule);
        self.apply_nat()?;
        Ok(())
    }

    /// Create VRF
    pub fn create_vrf(&self, name: &str) -> Result<(), EdgeError> {
        tracing::info!("Creating VRF: {}", name);
        let vrf = Vrf {
            name: name.to_string(),
            table_id: self.vrfs.read().len() as u32 + 100,
            interfaces: Vec::new(),
        };
        self.vrfs.write().insert(name.to_string(), vrf);
        // ip link add vrf-<name> type vrf table <id>
        Ok(())
    }

    /// Configure BGP
    pub fn configure_bgp(&self, config: BgpConfig) -> Result<(), EdgeError> {
        tracing::info!("Configuring BGP AS {}", config.local_as);
        *self.bgp.write() = Some(config);
        self.apply_bgp()?;
        Ok(())
    }

    /// Configure OSPF
    pub fn configure_ospf(&self, config: OspfConfig) -> Result<(), EdgeError> {
        tracing::info!("Configuring OSPF area {}", config.area);
        *self.ospf.write() = Some(config);
        self.apply_ospf()?;
        Ok(())
    }

    /// Get routing table
    pub fn get_routes(&self) -> Vec<Route> {
        self.routes.read().clone()
    }

    fn apply_routes(&self) -> Result<(), EdgeError> {
        // In production: ip route add/del commands
        Ok(())
    }

    fn apply_nat(&self) -> Result<(), EdgeError> {
        // In production: iptables -t nat rules
        Ok(())
    }

    fn apply_bgp(&self) -> Result<(), EdgeError> {
        // In production: FRRouting vtysh configuration
        Ok(())
    }

    fn apply_ospf(&self) -> Result<(), EdgeError> {
        // In production: FRRouting vtysh configuration
        Ok(())
    }
}

impl Default for RoutingEngine {
    fn default() -> Self { Self::new() }
}

/// Route entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: String,
    pub next_hop: String,
    pub interface: Option<String>,
    pub metric: u32,
    pub vrf: Option<String>,
}

/// Policy route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRoute {
    pub match_criteria: String,  // "src 10.0.0.0/24" or "app zoom"
    pub action: String,          // "route via wan1"
    pub priority: u32,
}

/// NAT rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub rule_type: NatType,
    pub source: String,
    pub destination: String,
    pub translated: String,
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NatType {
    Snat,
    Dnat,
    Masquerade,
}

/// VRF
#[derive(Debug, Clone)]
pub struct Vrf {
    pub name: String,
    pub table_id: u32,
    pub interfaces: Vec<String>,
}

/// BGP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    pub local_as: u32,
    pub router_id: String,
    pub neighbors: Vec<BgpNeighbor>,
    pub networks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNeighbor {
    pub address: String,
    pub remote_as: u32,
    pub password: Option<String>,
}

/// OSPF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfConfig {
    pub router_id: String,
    pub area: String,
    pub interfaces: Vec<String>,
    pub passive_interfaces: Vec<String>,
}
