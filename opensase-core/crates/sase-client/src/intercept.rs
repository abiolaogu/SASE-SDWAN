//! Traffic Interception
//!
//! Split tunneling and traffic routing decisions.

use std::collections::HashSet;
use std::net::IpAddr;

pub struct TrafficInterceptor {
    mode: parking_lot::RwLock<InterceptionMode>,
    bypass_apps: parking_lot::RwLock<HashSet<String>>,
    bypass_domains: parking_lot::RwLock<HashSet<String>>,
    bypass_ips: parking_lot::RwLock<HashSet<IpAddr>>,
    force_tunnel_apps: parking_lot::RwLock<HashSet<String>>,
    stats: parking_lot::RwLock<InterceptionStats>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptionMode {
    /// Tunnel all traffic except bypassed
    FullTunnel,
    /// Only tunnel specified traffic
    SplitTunnel,
    /// No tunneling (passthrough)
    Disabled,
}

#[derive(Clone, Debug, Default)]
pub struct InterceptionStats {
    pub packets_tunneled: u64,
    pub packets_bypassed: u64,
    pub bytes_tunneled: u64,
    pub bytes_bypassed: u64,
}

#[derive(Clone, Debug)]
pub struct TrafficDecision {
    pub tunnel: bool,
    pub reason: String,
    pub app: Option<String>,
    pub domain: Option<String>,
    pub dest_ip: Option<IpAddr>,
}

impl TrafficInterceptor {
    pub fn new() -> Self {
        Self {
            mode: parking_lot::RwLock::new(InterceptionMode::FullTunnel),
            bypass_apps: parking_lot::RwLock::new(HashSet::new()),
            bypass_domains: parking_lot::RwLock::new(HashSet::new()),
            bypass_ips: parking_lot::RwLock::new(HashSet::new()),
            force_tunnel_apps: parking_lot::RwLock::new(HashSet::new()),
            stats: parking_lot::RwLock::new(InterceptionStats::default()),
        }
    }
    
    /// Decide whether to tunnel traffic
    pub fn should_tunnel(
        &self,
        app: Option<&str>,
        domain: Option<&str>,
        dest_ip: Option<IpAddr>,
    ) -> TrafficDecision {
        let mode = *self.mode.read();
        
        match mode {
            InterceptionMode::Disabled => TrafficDecision {
                tunnel: false,
                reason: "Interception disabled".to_string(),
                app: app.map(|s| s.to_string()),
                domain: domain.map(|s| s.to_string()),
                dest_ip,
            },
            
            InterceptionMode::FullTunnel => {
                // Check bypass lists
                if let Some(app) = app {
                    if self.bypass_apps.read().contains(app) {
                        return TrafficDecision {
                            tunnel: false,
                            reason: format!("App {} is bypassed", app),
                            app: Some(app.to_string()),
                            domain: domain.map(|s| s.to_string()),
                            dest_ip,
                        };
                    }
                }
                
                if let Some(domain) = domain {
                    let bypass_domains = self.bypass_domains.read();
                    for bypass in bypass_domains.iter() {
                        if domain.ends_with(bypass) || domain == bypass {
                            return TrafficDecision {
                                tunnel: false,
                                reason: format!("Domain {} is bypassed", domain),
                                app: app.map(|s| s.to_string()),
                                domain: Some(domain.to_string()),
                                dest_ip,
                            };
                        }
                    }
                }
                
                if let Some(ip) = dest_ip {
                    if self.bypass_ips.read().contains(&ip) {
                        return TrafficDecision {
                            tunnel: false,
                            reason: format!("IP {} is bypassed", ip),
                            app: app.map(|s| s.to_string()),
                            domain: domain.map(|s| s.to_string()),
                            dest_ip: Some(ip),
                        };
                    }
                }
                
                // Default: tunnel
                TrafficDecision {
                    tunnel: true,
                    reason: "Full tunnel mode".to_string(),
                    app: app.map(|s| s.to_string()),
                    domain: domain.map(|s| s.to_string()),
                    dest_ip,
                }
            }
            
            InterceptionMode::SplitTunnel => {
                // Only tunnel if explicitly required
                if let Some(app) = app {
                    if self.force_tunnel_apps.read().contains(app) {
                        return TrafficDecision {
                            tunnel: true,
                            reason: format!("App {} requires tunnel", app),
                            app: Some(app.to_string()),
                            domain: domain.map(|s| s.to_string()),
                            dest_ip,
                        };
                    }
                }
                
                // Default: bypass
                TrafficDecision {
                    tunnel: false,
                    reason: "Split tunnel mode - not in forced list".to_string(),
                    app: app.map(|s| s.to_string()),
                    domain: domain.map(|s| s.to_string()),
                    dest_ip,
                }
            }
        }
    }
    
    pub fn set_mode(&self, mode: InterceptionMode) {
        *self.mode.write() = mode;
    }
    
    pub fn add_bypass_app(&self, app: &str) {
        self.bypass_apps.write().insert(app.to_string());
    }
    
    pub fn remove_bypass_app(&self, app: &str) {
        self.bypass_apps.write().remove(app);
    }
    
    pub fn add_bypass_domain(&self, domain: &str) {
        self.bypass_domains.write().insert(domain.to_string());
    }
    
    pub fn add_bypass_ip(&self, ip: IpAddr) {
        self.bypass_ips.write().insert(ip);
    }
    
    pub fn add_force_tunnel_app(&self, app: &str) {
        self.force_tunnel_apps.write().insert(app.to_string());
    }
    
    pub fn clear_bypass_lists(&self) {
        self.bypass_apps.write().clear();
        self.bypass_domains.write().clear();
        self.bypass_ips.write().clear();
    }
    
    pub fn record_tunneled(&self, bytes: u64) {
        let mut stats = self.stats.write();
        stats.packets_tunneled += 1;
        stats.bytes_tunneled += bytes;
    }
    
    pub fn record_bypassed(&self, bytes: u64) {
        let mut stats = self.stats.write();
        stats.packets_bypassed += 1;
        stats.bytes_bypassed += bytes;
    }
    
    pub fn stats(&self) -> InterceptionStats {
        self.stats.read().clone()
    }
}

impl Default for TrafficInterceptor {
    fn default() -> Self { Self::new() }
}
