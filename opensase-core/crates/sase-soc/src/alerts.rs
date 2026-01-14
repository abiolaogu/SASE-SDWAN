//! Alert Router
//!
//! Route alerts to appropriate destinations.

use crate::{SecurityAlert, Severity, AlertStatus};

pub struct AlertRouter {
    routes: dashmap::DashMap<String, AlertRoute>,
    alert_store: dashmap::DashMap<String, SecurityAlert>,
    stats: AlertStats,
}

struct AlertStats {
    total_received: std::sync::atomic::AtomicU64,
    total_routed: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct AlertRoute {
    pub id: String,
    pub name: String,
    pub condition: RouteCondition,
    pub destinations: Vec<AlertDestination>,
    pub enabled: bool,
}

#[derive(Clone)]
pub enum RouteCondition {
    All,
    Severity(Severity),
    AlertType(String),
    Tag(String),
}

#[derive(Clone)]
pub enum AlertDestination {
    Email { recipients: Vec<String> },
    Slack { channel: String, webhook: String },
    PagerDuty { service_key: String },
    Webhook { url: String },
    Case,
}

impl AlertRouter {
    pub fn new() -> Self {
        let router = Self {
            routes: dashmap::DashMap::new(),
            alert_store: dashmap::DashMap::new(),
            stats: AlertStats {
                total_received: std::sync::atomic::AtomicU64::new(0),
                total_routed: std::sync::atomic::AtomicU64::new(0),
            },
        };
        router.load_default_routes();
        router
    }
    
    fn load_default_routes(&self) {
        self.routes.insert("critical".to_string(), AlertRoute {
            id: "critical".to_string(),
            name: "Critical Alerts".to_string(),
            condition: RouteCondition::Severity(Severity::Critical),
            destinations: vec![
                AlertDestination::PagerDuty { service_key: "".to_string() },
                AlertDestination::Case,
            ],
            enabled: true,
        });
        
        self.routes.insert("high".to_string(), AlertRoute {
            id: "high".to_string(),
            name: "High Severity".to_string(),
            condition: RouteCondition::Severity(Severity::High),
            destinations: vec![
                AlertDestination::Slack { channel: "#security".to_string(), webhook: "".to_string() },
            ],
            enabled: true,
        });
    }
    
    pub async fn route(&self, alert: &SecurityAlert) {
        self.stats.total_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.alert_store.insert(alert.id.clone(), alert.clone());
        
        for route in self.routes.iter() {
            if !route.enabled { continue; }
            if !self.condition_matches(&route.condition, alert) { continue; }
            
            for dest in &route.destinations {
                self.send_to_destination(dest, alert).await;
            }
            self.stats.total_routed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    
    fn condition_matches(&self, condition: &RouteCondition, alert: &SecurityAlert) -> bool {
        match condition {
            RouteCondition::All => true,
            RouteCondition::Severity(s) => alert.severity >= *s,
            RouteCondition::AlertType(t) => &alert.alert_type == t,
            RouteCondition::Tag(t) => false, // TODO: check tags
        }
    }
    
    async fn send_to_destination(&self, dest: &AlertDestination, alert: &SecurityAlert) {
        match dest {
            AlertDestination::Email { recipients } => {
                tracing::info!("Routing alert {} to email: {:?}", alert.id, recipients);
            }
            AlertDestination::Slack { channel, .. } => {
                tracing::info!("Routing alert {} to Slack: {}", alert.id, channel);
            }
            AlertDestination::PagerDuty { .. } => {
                tracing::info!("Routing alert {} to PagerDuty", alert.id);
            }
            AlertDestination::Webhook { url } => {
                tracing::info!("Routing alert {} to webhook: {}", alert.id, url);
            }
            AlertDestination::Case => {
                tracing::info!("Creating case for alert {}", alert.id);
            }
        }
    }
    
    pub fn add_route(&self, route: AlertRoute) {
        self.routes.insert(route.id.clone(), route);
    }
    
    pub async fn get_open_count(&self) -> u64 {
        self.alert_store.iter()
            .filter(|a| a.status == AlertStatus::New || a.status == AlertStatus::InProgress)
            .count() as u64
    }
}

impl Default for AlertRouter {
    fn default() -> Self { Self::new() }
}
