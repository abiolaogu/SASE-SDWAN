//! Anycast Routing

use crate::pop::PopInstance;
use crate::health::{HealthMonitor, HealthStatus};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Anycast router - Routes traffic to nearest healthy PoP
pub struct AnycastRouter {
    /// Anycast IP → PoP mappings
    routes: Arc<RwLock<HashMap<String, Vec<AnycastRoute>>>>,
    /// Health monitor reference
    health: Arc<HealthMonitor>,
    /// BGP ASN
    asn: u32,
}

impl AnycastRouter {
    pub fn new(health: Arc<HealthMonitor>, asn: u32) -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            health,
            asn,
        }
    }

    /// Add anycast route
    pub fn add_route(&self, anycast_ip: &str, route: AnycastRoute) {
        let mut routes = self.routes.write();
        routes.entry(anycast_ip.to_string())
            .or_insert_with(Vec::new)
            .push(route);
    }

    /// Remove PoP from anycast
    pub fn remove_pop(&self, pop_id: &str) {
        let mut routes = self.routes.write();
        for routes in routes.values_mut() {
            routes.retain(|r| r.pop_id != pop_id);
        }
    }

    /// Get best PoP for anycast IP based on health and proximity
    pub fn get_best_pop(&self, anycast_ip: &str, client_ip: Option<&str>) -> Option<String> {
        let routes = self.routes.read();
        let candidates = routes.get(anycast_ip)?;

        // Filter healthy PoPs
        let healthy: Vec<_> = candidates.iter()
            .filter(|r| {
                self.health.get_status(&r.pop_id) == Some(HealthStatus::Healthy)
            })
            .collect();

        if healthy.is_empty() {
            // Fallback to degraded
            let degraded: Vec<_> = candidates.iter()
                .filter(|r| {
                    self.health.get_status(&r.pop_id) == Some(HealthStatus::Degraded)
                })
                .collect();
            
            return degraded.first().map(|r| r.pop_id.clone());
        }

        // Select by weight and health score
        let mut best: Option<&AnycastRoute> = None;
        let mut best_score = 0.0f32;

        for route in &healthy {
            let health_score = self.health.get_score(&route.pop_id).unwrap_or(0.0);
            let score = health_score * route.weight as f32;
            
            if score > best_score {
                best_score = score;
                best = Some(route);
            }
        }

        best.map(|r| r.pop_id.clone())
    }

    /// Generate BGP configuration for PoP
    pub fn generate_bgp_config(&self, pop_id: &str, anycast_ip: &str) -> String {
        format!(r#"
router bgp {asn}
  neighbor fabric peer-group
  neighbor fabric remote-as {asn}
  
  address-family ipv4 unicast
    network {anycast_ip}/32
    neighbor fabric activate
    neighbor fabric route-map ANYCAST-OUT out
  exit-address-family

route-map ANYCAST-OUT permit 10
  set community {asn}:{pop_id_num}
  set local-preference 100
"#, asn = self.asn, anycast_ip = anycast_ip, pop_id_num = pop_id.len())
    }

    /// Get all anycast IPs
    pub fn get_anycast_ips(&self) -> Vec<String> {
        self.routes.read().keys().cloned().collect()
    }

    /// Get PoPs for anycast IP
    pub fn get_pops(&self, anycast_ip: &str) -> Vec<String> {
        self.routes.read()
            .get(anycast_ip)
            .map(|routes| routes.iter().map(|r| r.pop_id.clone()).collect())
            .unwrap_or_default()
    }
}

/// Anycast route entry
#[derive(Debug, Clone)]
pub struct AnycastRoute {
    /// PoP ID
    pub pop_id: String,
    /// Route weight (higher = more traffic)
    pub weight: u32,
    /// BGP local preference
    pub local_pref: u32,
    /// Geographic coordinates for proximity
    pub latitude: f64,
    pub longitude: f64,
}

impl AnycastRoute {
    pub fn new(pop_id: &str, weight: u32) -> Self {
        Self {
            pop_id: pop_id.to_string(),
            weight,
            local_pref: 100,
            latitude: 0.0,
            longitude: 0.0,
        }
    }

    pub fn with_coords(mut self, lat: f64, lon: f64) -> Self {
        self.latitude = lat;
        self.longitude = lon;
        self
    }
}

/// Calculate haversine distance between coordinates
pub fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0; // Earth radius in km
    
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() 
        * lat2.to_radians().cos() 
        * (d_lon / 2.0).sin().powi(2);
    
    let c = 2.0 * a.sqrt().asin();
    R * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine() {
        // NYC to London ~5,570 km
        let dist = haversine_distance(40.7128, -74.0060, 51.5074, -0.1278);
        assert!((dist - 5570.0).abs() < 50.0);
    }

    #[test]
    fn test_anycast_routing() {
        let health = Arc::new(HealthMonitor::new());
        let router = AnycastRouter::new(health.clone(), 65000);
        
        health.register("pop-us", vec![]);
        health.register("pop-eu", vec![]);
        
        router.add_route("192.0.2.1", AnycastRoute::new("pop-us", 100));
        router.add_route("192.0.2.1", AnycastRoute::new("pop-eu", 100));
        
        let pops = router.get_pops("192.0.2.1");
        assert_eq!(pops.len(), 2);
    }
}
