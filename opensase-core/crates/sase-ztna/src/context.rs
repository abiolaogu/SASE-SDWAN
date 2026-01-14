//! Access Context Evaluation
//!
//! Build and evaluate access context for policy decisions.

use crate::{AccessContext, AccessRequest, GeoLocation, NetworkType, RiskSignal, RiskSignalType, RiskSeverity};
use std::net::IpAddr;

/// Context builder and evaluator
pub struct ContextEvaluator {
    /// Geo IP database
    geoip: GeoIpDb,
    /// Known corporate networks
    corporate_networks: Vec<ipnetwork::IpNetwork>,
    /// VPN exit IPs
    vpn_ips: std::collections::HashSet<IpAddr>,
}

struct GeoIpDb;

impl GeoIpDb {
    fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        // In production: use MaxMind GeoIP2
        tracing::debug!("GeoIP lookup for {}", ip);
        None
    }
}

impl ContextEvaluator {
    pub fn new() -> Self {
        Self {
            geoip: GeoIpDb,
            corporate_networks: vec![],
            vpn_ips: std::collections::HashSet::new(),
        }
    }
    
    /// Build access context
    pub fn build_context(
        &self,
        client_ip: IpAddr,
        user_agent: &str,
        session_id: Option<String>,
    ) -> AccessContext {
        let geo_location = self.geoip.lookup(client_ip);
        let network_type = self.determine_network_type(client_ip);
        
        AccessContext {
            client_ip,
            geo_location,
            network_type,
            time_of_access: chrono::Utc::now(),
            session_id,
            user_agent: user_agent.to_string(),
            risk_score: 0.0,
            signals: vec![],
        }
    }
    
    fn determine_network_type(&self, ip: IpAddr) -> NetworkType {
        // Check corporate networks
        for network in &self.corporate_networks {
            if network.contains(ip) {
                return NetworkType::Corporate;
            }
        }
        
        // Check VPN
        if self.vpn_ips.contains(&ip) {
            return NetworkType::VPN;
        }
        
        // Check if private IP (home network)
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                if (octets[0] == 10) ||
                   (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                   (octets[0] == 192 && octets[1] == 168) {
                    return NetworkType::Home;
                }
            }
            IpAddr::V6(_) => {}
        }
        
        NetworkType::Unknown
    }
    
    /// Evaluate context for risk signals
    pub fn evaluate(&self, request: &AccessRequest, history: &UserHistory) -> Vec<RiskSignal> {
        let mut signals = Vec::new();
        
        // Check impossible travel
        if let Some(signal) = self.check_impossible_travel(request, history) {
            signals.push(signal);
        }
        
        // Check new device
        if let Some(signal) = self.check_new_device(request, history) {
            signals.push(signal);
        }
        
        // Check new location
        if let Some(signal) = self.check_new_location(request, history) {
            signals.push(signal);
        }
        
        // Check unusual time
        if let Some(signal) = self.check_unusual_time(request, history) {
            signals.push(signal);
        }
        
        signals
    }
    
    fn check_impossible_travel(&self, request: &AccessRequest, history: &UserHistory) -> Option<RiskSignal> {
        if let (Some(last_location), Some(current_location)) = 
            (&history.last_location, &request.context.geo_location) 
        {
            let distance = haversine_distance(
                last_location.latitude, last_location.longitude,
                current_location.latitude, current_location.longitude,
            );
            
            let time_diff = (request.context.time_of_access - history.last_access)
                .num_minutes() as f64;
            
            // Assume max 900 km/h (airplane)
            let max_distance = time_diff * 15.0; // 15 km per minute
            
            if distance > max_distance {
                return Some(RiskSignal {
                    signal_type: RiskSignalType::ImpossibleTravel,
                    severity: RiskSeverity::High,
                    description: format!(
                        "Travel of {:.0} km in {:.0} minutes is impossible",
                        distance, time_diff
                    ),
                    detected_at: chrono::Utc::now(),
                });
            }
        }
        
        None
    }
    
    fn check_new_device(&self, request: &AccessRequest, history: &UserHistory) -> Option<RiskSignal> {
        if !history.known_devices.contains(&request.device.id) {
            return Some(RiskSignal {
                signal_type: RiskSignalType::NewDevice,
                severity: RiskSeverity::Medium,
                description: format!("Access from new device: {}", request.device.name),
                detected_at: chrono::Utc::now(),
            });
        }
        None
    }
    
    fn check_new_location(&self, request: &AccessRequest, history: &UserHistory) -> Option<RiskSignal> {
        if let Some(geo) = &request.context.geo_location {
            if !history.known_countries.contains(&geo.country) {
                return Some(RiskSignal {
                    signal_type: RiskSignalType::NewLocation,
                    severity: RiskSeverity::Medium,
                    description: format!("Access from new country: {}", geo.country),
                    detected_at: chrono::Utc::now(),
                });
            }
        }
        None
    }
    
    fn check_unusual_time(&self, request: &AccessRequest, history: &UserHistory) -> Option<RiskSignal> {
        let hour = request.context.time_of_access.time().hour();
        
        // Check if outside normal working hours and user typically works business hours
        if history.typical_access_hours.is_some() {
            let (start, end) = history.typical_access_hours.unwrap();
            if hour < start || hour > end {
                return Some(RiskSignal {
                    signal_type: RiskSignalType::UnusualTime,
                    severity: RiskSeverity::Low,
                    description: format!("Access at unusual hour: {}", hour),
                    detected_at: chrono::Utc::now(),
                });
            }
        }
        
        None
    }
    
    /// Add corporate network
    pub fn add_corporate_network(&mut self, network: ipnetwork::IpNetwork) {
        self.corporate_networks.push(network);
    }
}

impl Default for ContextEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

/// User access history
pub struct UserHistory {
    pub last_location: Option<GeoLocation>,
    pub last_access: chrono::DateTime<chrono::Utc>,
    pub known_devices: std::collections::HashSet<String>,
    pub known_countries: std::collections::HashSet<String>,
    pub typical_access_hours: Option<(u8, u8)>,
}

impl Default for UserHistory {
    fn default() -> Self {
        Self {
            last_location: None,
            last_access: chrono::Utc::now(),
            known_devices: std::collections::HashSet::new(),
            known_countries: std::collections::HashSet::new(),
            typical_access_hours: Some((8, 18)), // 8 AM - 6 PM
        }
    }
}

fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    
    let a = (dlat / 2.0).sin().powi(2) +
            lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    
    EARTH_RADIUS_KM * c
}

use chrono::Timelike;
