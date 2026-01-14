//! Enhanced Micro-Segmentation
//!
//! Per-app isolation with WireGuard micro-tunnels.

use crate::{Session, Resource};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Enhanced micro-segmentation engine
pub struct EnhancedMicroSeg {
    tunnels: dashmap::DashMap<String, MicroTunnel>,
    acl_rules: dashmap::DashMap<String, Vec<AclRule>>,
    app_connectors: dashmap::DashMap<String, AppConnectorConfig>,
}

/// Micro-tunnel for per-app isolation
#[derive(Clone)]
pub struct MicroTunnel {
    pub id: String,
    pub session_id: String,
    pub app_id: String,
    pub user_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub wireguard_config: WgTunnelConfig,
    pub connection_info: ConnectionInfo,
    pub state: TunnelState,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

#[derive(Clone)]
pub struct WgTunnelConfig {
    pub public_key: String,
    pub private_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
}

#[derive(Clone)]
pub struct ConnectionInfo {
    pub gateway: SocketAddr,
    pub port: u16,
    pub client_config: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Pending,
    Active,
    Suspended,
    Expired,
    Terminated,
}

/// ACL rule for micro-segmentation
#[derive(Clone)]
pub struct AclRule {
    pub id: String,
    pub priority: u32,
    pub action: AclAction,
    pub src: AclMatch,
    pub dst: AclMatch,
    pub protocol: AclProtocol,
    pub logging: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    Allow,
    Deny,
    Log,
    Inspect,
}

#[derive(Clone)]
pub enum AclMatch {
    Any,
    TunnelId(String),
    IpAddr(IpAddr),
    IpPort { ip: IpAddr, port: u16 },
    Cidr(String),
    AppId(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AclProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

/// App connector configuration
#[derive(Clone)]
pub struct AppConnectorConfig {
    pub id: String,
    pub app_id: String,
    pub internal_host: String,
    pub internal_port: u16,
    pub protocol: AclProtocol,
    pub health_check: HealthCheckConfig,
}

#[derive(Clone)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub path: Option<String>,
}

impl EnhancedMicroSeg {
    pub fn new() -> Self {
        Self {
            tunnels: dashmap::DashMap::new(),
            acl_rules: dashmap::DashMap::new(),
            app_connectors: dashmap::DashMap::new(),
        }
    }
    
    /// Create micro-tunnel for session+app
    pub async fn create_tunnel(
        &self,
        session: &Session,
        app: &AppConnectorConfig,
    ) -> Result<MicroTunnel, MicroSegError> {
        // Generate WireGuard keypair
        let (public_key, private_key) = self.generate_wg_keypair();
        
        // Create tunnel config
        let tunnel = MicroTunnel {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            app_id: app.app_id.clone(),
            user_id: session.identity.user_id.clone(),
            created_at: chrono::Utc::now(),
            expires_at: session.expires_at,
            wireguard_config: WgTunnelConfig {
                public_key: public_key.clone(),
                private_key,
                allowed_ips: vec![format!("{}/32", app.internal_host)],
                endpoint: None,
                keepalive: 25,
            },
            connection_info: ConnectionInfo {
                gateway: "0.0.0.0:51820".parse().unwrap(),
                port: 51820,
                client_config: self.generate_client_config(&public_key, app),
            },
            state: TunnelState::Pending,
            bytes_tx: 0,
            bytes_rx: 0,
        };
        
        // Apply micro-segmentation ACL
        self.apply_tunnel_acl(&tunnel, app).await?;
        
        // Store tunnel
        self.tunnels.insert(tunnel.id.clone(), tunnel.clone());
        
        tracing::info!(
            "Created micro-tunnel {} for session {} to app {}",
            tunnel.id, session.id, app.app_id
        );
        
        Ok(tunnel)
    }
    
    fn generate_wg_keypair(&self) -> (String, String) {
        // In production: use actual WireGuard key generation
        (
            base64::encode(uuid::Uuid::new_v4().as_bytes()),
            base64::encode(uuid::Uuid::new_v4().as_bytes()),
        )
    }
    
    fn generate_client_config(&self, _public_key: &str, app: &AppConnectorConfig) -> String {
        format!(r#"
[Interface]
PrivateKey = <client_private_key>
Address = 10.200.0.2/32
DNS = 10.200.0.1

[Peer]
PublicKey = <gateway_public_key>
Endpoint = gateway.example.com:51820
AllowedIPs = {}/32
PersistentKeepalive = 25
"#, app.internal_host)
    }
    
    /// Apply ACL rules for tunnel
    async fn apply_tunnel_acl(&self, tunnel: &MicroTunnel, app: &AppConnectorConfig) -> Result<(), MicroSegError> {
        let rules = vec![
            // Allow traffic to specific app only
            AclRule {
                id: format!("allow-{}-{}", tunnel.id, app.app_id),
                priority: 100,
                action: AclAction::Allow,
                src: AclMatch::TunnelId(tunnel.id.clone()),
                dst: AclMatch::IpPort {
                    ip: app.internal_host.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                    port: app.internal_port,
                },
                protocol: app.protocol,
                logging: true,
            },
            // Deny all other traffic from this tunnel
            AclRule {
                id: format!("deny-{}-all", tunnel.id),
                priority: 1000,
                action: AclAction::Deny,
                src: AclMatch::TunnelId(tunnel.id.clone()),
                dst: AclMatch::Any,
                protocol: AclProtocol::Any,
                logging: true,
            },
        ];
        
        self.acl_rules.insert(tunnel.id.clone(), rules);
        
        Ok(())
    }
    
    /// Activate tunnel
    pub async fn activate_tunnel(&self, tunnel_id: &str) -> Result<(), MicroSegError> {
        if let Some(mut tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.state = TunnelState::Active;
            tracing::info!("Activated tunnel {}", tunnel_id);
            Ok(())
        } else {
            Err(MicroSegError::TunnelNotFound)
        }
    }
    
    /// Terminate tunnel
    pub async fn terminate_tunnel(&self, tunnel_id: &str) {
        if let Some(mut tunnel) = self.tunnels.get_mut(tunnel_id) {
            tunnel.state = TunnelState::Terminated;
        }
        
        // Remove ACL rules
        self.acl_rules.remove(tunnel_id);
        
        tracing::info!("Terminated tunnel {}", tunnel_id);
    }
    
    /// Terminate all tunnels for session
    pub async fn terminate_session_tunnels(&self, session_id: &str) {
        let tunnel_ids: Vec<String> = self.tunnels.iter()
            .filter(|t| t.session_id == session_id)
            .map(|t| t.id.clone())
            .collect();
        
        for id in tunnel_ids {
            self.terminate_tunnel(&id).await;
        }
    }
    
    /// Check if traffic is allowed
    pub fn check_traffic(
        &self,
        tunnel_id: &str,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: AclProtocol,
    ) -> AclAction {
        if let Some(rules) = self.acl_rules.get(tunnel_id) {
            let mut sorted_rules = rules.clone();
            sorted_rules.sort_by(|a, b| a.priority.cmp(&b.priority));
            
            for rule in sorted_rules {
                if self.rule_matches(&rule, tunnel_id, dst_ip, dst_port, protocol) {
                    if rule.logging {
                        tracing::debug!(
                            "ACL {} {} traffic from tunnel {} to {}:{}",
                            rule.id, 
                            if rule.action == AclAction::Allow { "allowing" } else { "denying" },
                            tunnel_id, dst_ip, dst_port
                        );
                    }
                    return rule.action;
                }
            }
        }
        
        // Default deny
        AclAction::Deny
    }
    
    fn rule_matches(
        &self,
        rule: &AclRule,
        tunnel_id: &str,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: AclProtocol,
    ) -> bool {
        // Check source
        let src_match = match &rule.src {
            AclMatch::Any => true,
            AclMatch::TunnelId(id) => id == tunnel_id,
            _ => false,
        };
        
        // Check destination
        let dst_match = match &rule.dst {
            AclMatch::Any => true,
            AclMatch::IpAddr(ip) => *ip == dst_ip,
            AclMatch::IpPort { ip, port } => *ip == dst_ip && *port == dst_port,
            _ => false,
        };
        
        // Check protocol
        let proto_match = rule.protocol == AclProtocol::Any || rule.protocol == protocol;
        
        src_match && dst_match && proto_match
    }
    
    /// Register app connector
    pub fn register_connector(&self, config: AppConnectorConfig) {
        self.app_connectors.insert(config.id.clone(), config);
    }
    
    /// Get tunnel stats
    pub fn get_tunnel_stats(&self, tunnel_id: &str) -> Option<TunnelStats> {
        self.tunnels.get(tunnel_id).map(|t| TunnelStats {
            id: t.id.clone(),
            state: t.state,
            bytes_tx: t.bytes_tx,
            bytes_rx: t.bytes_rx,
            created_at: t.created_at,
            expires_at: t.expires_at,
        })
    }
}

impl Default for EnhancedMicroSeg {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TunnelStats {
    pub id: String,
    pub state: TunnelState,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub enum MicroSegError {
    TunnelNotFound,
    AclError,
    WireGuardError,
}

impl std::fmt::Display for MicroSegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TunnelNotFound => write!(f, "Tunnel not found"),
            Self::AclError => write!(f, "ACL error"),
            Self::WireGuardError => write!(f, "WireGuard error"),
        }
    }
}

impl std::error::Error for MicroSegError {}

use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64;
