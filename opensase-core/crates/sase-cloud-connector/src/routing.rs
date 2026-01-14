//! Multi-cloud routing management
//!
//! Handles route management across multiple cloud connections with failover support.

use crate::{CloudConnection, CloudRoute, ConnectorError};
use ipnet::IpNet;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Cloud route manager
pub struct CloudRouteManager {
    routes: Arc<RwLock<RouteTable>>,
    failover_pairs: Arc<RwLock<HashMap<uuid::Uuid, uuid::Uuid>>>,
}

/// Route table
#[derive(Default)]
pub struct RouteTable {
    pub routes: HashMap<IpNet, Vec<CloudRoute>>,
    pub default_routes: Vec<CloudRoute>,
}

/// Routing strategy
#[derive(Clone, Debug)]
pub enum RoutingStrategy {
    /// Active/Passive failover
    ActivePassive {
        primary: uuid::Uuid,
        backup: uuid::Uuid,
    },
    /// Active/Active load balancing
    ActiveActive {
        connections: Vec<uuid::Uuid>,
        load_balancing: LoadBalancing,
    },
    /// Latency-based routing
    LatencyBased {
        connections: Vec<uuid::Uuid>,
    },
    /// Cost-based routing
    CostBased {
        connections: Vec<uuid::Uuid>,
        cost_weights: HashMap<uuid::Uuid, f64>,
    },
}

/// Load balancing method
#[derive(Clone, Debug)]
pub enum LoadBalancing {
    RoundRobin,
    Weighted(HashMap<uuid::Uuid, u32>),
    LeastConnections,
}

impl CloudRouteManager {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(RouteTable::default())),
            failover_pairs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Add a route
    pub fn add_route(&self, route: CloudRoute) {
        let mut table = self.routes.write();
        table.routes
            .entry(route.prefix)
            .or_insert_with(Vec::new)
            .push(route);
    }
    
    /// Remove a route
    pub fn remove_route(&self, prefix: &IpNet, connection_id: &uuid::Uuid) {
        let mut table = self.routes.write();
        if let Some(routes) = table.routes.get_mut(prefix) {
            routes.retain(|r| r.connection_id != *connection_id);
        }
    }
    
    /// Get routes for a prefix
    pub fn get_routes(&self, prefix: &IpNet) -> Vec<CloudRoute> {
        let table = self.routes.read();
        table.routes.get(prefix).cloned().unwrap_or_default()
    }
    
    /// Get all routes
    pub fn get_all_routes(&self) -> HashMap<IpNet, Vec<CloudRoute>> {
        self.routes.read().routes.clone()
    }
    
    /// Configure failover pair
    pub fn configure_failover_pair(&self, primary: &CloudConnection, backup: &CloudConnection) {
        self.failover_pairs.write().insert(primary.id, backup.id);
        
        // Set priorities: primary = 200, backup = 100
        let mut table = self.routes.write();
        for routes in table.routes.values_mut() {
            for route in routes.iter_mut() {
                if route.connection_id == primary.id {
                    route.priority = 200;
                } else if route.connection_id == backup.id {
                    route.priority = 100;
                }
            }
        }
    }
    
    /// Activate backup when primary fails
    pub fn activate_backup(&self, failed: &CloudConnection, backup: &CloudConnection) {
        let mut table = self.routes.write();
        
        for routes in table.routes.values_mut() {
            for route in routes.iter_mut() {
                if route.connection_id == failed.id {
                    route.active = false;
                } else if route.connection_id == backup.id {
                    route.active = true;
                    route.priority = 200; // Promote backup
                }
            }
        }
    }
    
    /// Get best route for a destination
    pub fn get_best_route(&self, destination: &IpNet) -> Option<CloudRoute> {
        let table = self.routes.read();
        
        // Find longest prefix match
        let mut best_match: Option<(&IpNet, &Vec<CloudRoute>)> = None;
        
        for (prefix, routes) in &table.routes {
            if prefix.contains(destination) {
                match best_match {
                    None => best_match = Some((prefix, routes)),
                    Some((current, _)) if prefix.prefix_len() > current.prefix_len() => {
                        best_match = Some((prefix, routes));
                    }
                    _ => {}
                }
            }
        }
        
        // Return highest priority active route
        best_match.and_then(|(_, routes)| {
            routes
                .iter()
                .filter(|r| r.active)
                .max_by_key(|r| r.priority)
                .cloned()
        })
    }
    
    /// Apply routing strategy
    pub fn apply_strategy(&self, strategy: RoutingStrategy) {
        match strategy {
            RoutingStrategy::ActivePassive { primary, backup } => {
                self.set_priorities(&[(primary, 200), (backup, 100)]);
            }
            RoutingStrategy::ActiveActive { connections, load_balancing } => {
                match load_balancing {
                    LoadBalancing::RoundRobin => {
                        // Equal weights
                        let weight = 100 / connections.len() as u32;
                        for conn_id in connections {
                            self.set_weight(&conn_id, weight);
                        }
                    }
                    LoadBalancing::Weighted(weights) => {
                        for (conn_id, weight) in weights {
                            self.set_weight(&conn_id, weight);
                        }
                    }
                    LoadBalancing::LeastConnections => {
                        // Would need connection tracking
                    }
                }
            }
            RoutingStrategy::LatencyBased { connections: _ } => {
                // Would need latency measurements
            }
            RoutingStrategy::CostBased { connections: _, cost_weights } => {
                // Route based on egress cost
                for (conn_id, cost) in cost_weights {
                    // Lower cost = higher priority
                    let priority = ((1.0 / cost) * 100.0) as u32;
                    self.set_priorities(&[(conn_id, priority)]);
                }
            }
        }
    }
    
    fn set_priorities(&self, priorities: &[(uuid::Uuid, u32)]) {
        let mut table = self.routes.write();
        for routes in table.routes.values_mut() {
            for route in routes.iter_mut() {
                for (conn_id, priority) in priorities {
                    if route.connection_id == *conn_id {
                        route.priority = *priority;
                    }
                }
            }
        }
    }
    
    fn set_weight(&self, connection_id: &uuid::Uuid, weight: u32) {
        let mut table = self.routes.write();
        for routes in table.routes.values_mut() {
            for route in routes.iter_mut() {
                if route.connection_id == *connection_id {
                    route.weight = weight;
                }
            }
        }
    }
    
    /// Generate BIRD route filter
    pub fn generate_bird_filter(&self, tenant_prefix: &str) -> String {
        let table = self.routes.read();
        
        let mut filter = format!(r#"
filter {tenant_prefix}_export {{
    # Export only tenant prefixes
"#);
        
        for prefix in table.routes.keys() {
            filter.push_str(&format!("    if net = {} then accept;\n", prefix));
        }
        
        filter.push_str("    reject;\n}\n");
        filter
    }
}

impl Default for CloudRouteManager {
    fn default() -> Self {
        Self::new()
    }
}
