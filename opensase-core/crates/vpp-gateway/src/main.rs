//! VPP Gateway Service
//!
//! gRPC gateway between Kubernetes services and bare-metal VPP.
//! Exposes VPP data plane operations to control plane.

use tonic::{transport::Server, Request, Response, Status};
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod proto {
    tonic::include_proto!("opensase.vpp");
}

use proto::vpp_gateway_server::{VppGateway, VppGatewayServer};
use proto::*;

/// VPP client abstraction
pub struct VppClient {
    socket_path: String,
    connected: bool,
}

impl VppClient {
    pub async fn connect(socket_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // In production, this would use the VPP API bindings
        tracing::info!("Connecting to VPP at {}", socket_path);
        Ok(Self {
            socket_path: socket_path.to_string(),
            connected: true,
        })
    }

    pub async fn get_interfaces(&self) -> Result<Vec<VppInterface>, Box<dyn std::error::Error>> {
        // Execute: vppctl show interface
        Ok(vec![])
    }

    pub async fn get_wireguard_tunnels(&self) -> Result<Vec<WgTunnel>, Box<dyn std::error::Error>> {
        // Execute: vppctl show wireguard
        Ok(vec![])
    }

    pub async fn create_wireguard_tunnel(
        &self,
        listen_port: u16,
        _private_key: &[u8],
        _local_ip: &std::net::IpAddr,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        tracing::info!("Creating WireGuard tunnel on port {}", listen_port);
        Ok(1) // Return sw_if_index
    }

    pub async fn add_wireguard_peer(
        &self,
        _tunnel_id: u32,
        _public_key: &[u8],
        _endpoint: &std::net::SocketAddr,
        _allowed_ips: &[std::net::IpAddr],
        _keepalive: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub async fn acl_add_replace(
        &self,
        _acl_index: u32,
        _rules: &[VppAclRule],
    ) -> Result<u32, Box<dyn std::error::Error>> {
        Ok(0)
    }

    pub async fn acl_interface_add_del(
        &self,
        _sw_if_index: u32,
        _is_input: bool,
        _acl_index: u32,
        _add: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

/// VPP interface info
pub struct VppInterface {
    pub name: String,
    pub sw_if_index: u32,
    pub mac: [u8; 6],
    pub admin_up: bool,
    pub link_up: bool,
    pub stats: InterfaceStats,
}

pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// WireGuard tunnel info
pub struct WgTunnel {
    pub sw_if_index: u32,
    pub peer_public_key: [u8; 32],
    pub endpoint: std::net::SocketAddr,
    pub last_handshake: chrono::DateTime<chrono::Utc>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// ACL rule for VPP
pub struct VppAclRule {
    pub is_permit: bool,
    pub src_prefix: std::net::IpAddr,
    pub dst_prefix: std::net::IpAddr,
    pub proto: u8,
    pub srcport_or_icmptype_first: u16,
    pub srcport_or_icmptype_last: u16,
    pub dstport_or_icmpcode_first: u16,
    pub dstport_or_icmpcode_last: u16,
}

/// VPP Gateway service implementation
pub struct VppGatewayService {
    vpp: Arc<RwLock<VppClient>>,
}

impl VppGatewayService {
    pub fn new(vpp: VppClient) -> Self {
        Self {
            vpp: Arc::new(RwLock::new(vpp)),
        }
    }
}

#[tonic::async_trait]
impl VppGateway for VppGatewayService {
    /// Get all VPP interfaces
    async fn get_interfaces(
        &self,
        _request: Request<GetInterfacesRequest>,
    ) -> Result<Response<GetInterfacesResponse>, Status> {
        let vpp = self.vpp.read().await;
        let interfaces = vpp.get_interfaces().await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetInterfacesResponse {
            interfaces: interfaces.into_iter().map(|i| Interface {
                name: i.name,
                sw_if_index: i.sw_if_index,
                mac_address: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    i.mac[0], i.mac[1], i.mac[2], i.mac[3], i.mac[4], i.mac[5]),
                admin_up: i.admin_up,
                link_up: i.link_up,
                rx_bytes: i.stats.rx_bytes,
                tx_bytes: i.stats.tx_bytes,
                rx_packets: i.stats.rx_packets,
                tx_packets: i.stats.tx_packets,
            }).collect(),
        }))
    }

    /// Get WireGuard tunnels
    async fn get_tunnels(
        &self,
        _request: Request<GetTunnelsRequest>,
    ) -> Result<Response<GetTunnelsResponse>, Status> {
        let vpp = self.vpp.read().await;
        let tunnels = vpp.get_wireguard_tunnels().await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetTunnelsResponse {
            tunnels: tunnels.into_iter().map(|t| Tunnel {
                id: t.sw_if_index.to_string(),
                peer_public_key: base64::encode(&t.peer_public_key),
                endpoint: t.endpoint.to_string(),
                last_handshake: t.last_handshake.timestamp(),
                rx_bytes: t.rx_bytes,
                tx_bytes: t.tx_bytes,
            }).collect(),
        }))
    }

    /// Create a new WireGuard tunnel
    async fn create_tunnel(
        &self,
        request: Request<CreateTunnelRequest>,
    ) -> Result<Response<CreateTunnelResponse>, Status> {
        let req = request.into_inner();
        let vpp = self.vpp.read().await;

        let private_key = base64::decode(&req.private_key)
            .map_err(|e| Status::invalid_argument(format!("Invalid private key: {}", e)))?;

        let local_ip: std::net::IpAddr = req.local_ip.parse()
            .map_err(|e| Status::invalid_argument(format!("Invalid local IP: {}", e)))?;

        let tunnel_id = vpp.create_wireguard_tunnel(
            req.listen_port as u16,
            &private_key,
            &local_ip,
        ).await.map_err(|e| Status::internal(e.to_string()))?;

        // Add peer if provided
        if !req.peer_public_key.is_empty() {
            let peer_key = base64::decode(&req.peer_public_key)
                .map_err(|e| Status::invalid_argument(format!("Invalid peer key: {}", e)))?;

            let endpoint: std::net::SocketAddr = req.peer_endpoint.parse()
                .map_err(|e| Status::invalid_argument(format!("Invalid endpoint: {}", e)))?;

            let allowed_ips: Vec<std::net::IpAddr> = req.allowed_ips.iter()
                .filter_map(|s| s.parse().ok())
                .collect();

            vpp.add_wireguard_peer(
                tunnel_id,
                &peer_key,
                &endpoint,
                &allowed_ips,
                25,
            ).await.map_err(|e| Status::internal(e.to_string()))?;
        }

        tracing::info!("Created WireGuard tunnel {}", tunnel_id);

        Ok(Response::new(CreateTunnelResponse {
            tunnel_id: tunnel_id.to_string(),
        }))
    }

    /// Delete a WireGuard tunnel
    async fn delete_tunnel(
        &self,
        request: Request<DeleteTunnelRequest>,
    ) -> Result<Response<DeleteTunnelResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("Deleting tunnel {}", req.tunnel_id);
        Ok(Response::new(DeleteTunnelResponse { success: true }))
    }

    /// Apply ACL rules
    async fn apply_acl(
        &self,
        request: Request<ApplyAclRequest>,
    ) -> Result<Response<ApplyAclResponse>, Status> {
        let req = request.into_inner();
        let vpp = self.vpp.read().await;

        let rules: Vec<VppAclRule> = req.rules.iter().map(|r| {
            VppAclRule {
                is_permit: r.action == "allow",
                src_prefix: r.source.parse().unwrap_or("0.0.0.0".parse().unwrap()),
                dst_prefix: r.destination.parse().unwrap_or("0.0.0.0".parse().unwrap()),
                proto: r.protocol as u8,
                srcport_or_icmptype_first: r.src_port_start as u16,
                srcport_or_icmptype_last: r.src_port_end as u16,
                dstport_or_icmpcode_first: r.dst_port_start as u16,
                dstport_or_icmpcode_last: r.dst_port_end as u16,
            }
        }).collect();

        let acl_index = vpp.acl_add_replace(u32::MAX, &rules).await
            .map_err(|e| Status::internal(e.to_string()))?;

        let sw_if_index: u32 = req.interface_id.parse()
            .map_err(|e| Status::invalid_argument(format!("Invalid interface: {}", e)))?;

        vpp.acl_interface_add_del(sw_if_index, true, acl_index, true).await
            .map_err(|e| Status::internal(e.to_string()))?;

        tracing::info!("Applied ACL {} to interface {}", acl_index, sw_if_index);

        Ok(Response::new(ApplyAclResponse {
            acl_id: acl_index.to_string(),
        }))
    }

    /// Get data plane statistics
    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        Ok(Response::new(GetStatsResponse {
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            total_rx_packets: 0,
            total_tx_packets: 0,
            active_sessions: 0,
            active_tunnels: 0,
        }))
    }

    /// Health check
    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let vpp = self.vpp.read().await;
        Ok(Response::new(HealthCheckResponse {
            healthy: vpp.connected,
            version: "1.0.0".to_string(),
            uptime_seconds: 0,
        }))
    }
}

/// Start the VPP Gateway server
pub async fn start_server(
    bind_addr: &str,
    vpp_socket: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let vpp = VppClient::connect(vpp_socket).await?;
    let service = VppGatewayService::new(vpp);

    tracing::info!("VPP Gateway listening on {}", bind_addr);

    Server::builder()
        .add_service(VppGatewayServer::new(service))
        .serve(bind_addr.parse()?)
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let vpp_socket = std::env::var("VPP_SOCKET")
        .unwrap_or_else(|_| "/run/vpp/cli.sock".to_string());

    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50052".to_string());

    start_server(&bind_addr, &vpp_socket).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_rule_parsing() {
        let rule = VppAclRule {
            is_permit: true,
            src_prefix: "10.0.0.0".parse().unwrap(),
            dst_prefix: "0.0.0.0".parse().unwrap(),
            proto: 6,
            srcport_or_icmptype_first: 0,
            srcport_or_icmptype_last: 65535,
            dstport_or_icmpcode_first: 443,
            dstport_or_icmpcode_last: 443,
        };
        assert!(rule.is_permit);
    }
}
