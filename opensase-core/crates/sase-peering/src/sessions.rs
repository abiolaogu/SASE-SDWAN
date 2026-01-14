//! BGP Session Management
//!
//! Manages peering sessions with ISPs and content networks at IXPs.

use crate::{
    PeeringSession, PeeringType, BgpSessionState, PeerNetwork, 
    IxpPort, PeeringPolicy, OPENSASE_ASN
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Session manager
pub struct SessionManager {
    sessions: HashMap<String, PeeringSession>,
    pending_requests: Vec<PeeringRequest>,
}

/// Peering request to a network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeeringRequest {
    pub id: String,
    pub peer_asn: u32,
    pub peer_name: String,
    pub ixp_id: u32,
    pub ixp_name: String,
    pub our_ip: IpAddr,
    pub peer_ip: IpAddr,
    pub requested_at: i64,
    pub status: RequestStatus,
    pub contact_email: Option<String>,
    pub notes: Option<String>,
}

/// Request status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    Draft,
    Sent,
    Acknowledged,
    Approved,
    Rejected,
    Expired,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub peer_asn: u32,
    pub peer_ip: IpAddr,
    pub local_ip: IpAddr,
    pub md5_password: Option<String>,
    pub max_prefix_v4: u32,
    pub max_prefix_v6: u32,
    pub enable_graceful_restart: bool,
    pub hold_time: u16,
    pub keepalive_time: u16,
}

impl SessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            pending_requests: Vec::new(),
        }
    }

    /// Add peering session
    pub fn add_session(&mut self, session: PeeringSession) {
        self.sessions.insert(session.id.clone(), session);
    }

    /// Get session by ID
    pub fn get_session(&self, id: &str) -> Option<&PeeringSession> {
        self.sessions.get(id)
    }

    /// Get sessions at an IXP port
    pub fn get_port_sessions(&self, port_id: &str) -> Vec<&PeeringSession> {
        self.sessions.values()
            .filter(|s| s.ixp_port_id == port_id)
            .collect()
    }

    /// Get established sessions
    pub fn established_sessions(&self) -> Vec<&PeeringSession> {
        self.sessions.values()
            .filter(|s| s.state == BgpSessionState::Established)
            .collect()
    }

    /// Get sessions by peer ASN
    pub fn get_peer_sessions(&self, asn: u32) -> Vec<&PeeringSession> {
        self.sessions.values()
            .filter(|s| s.peer_asn == asn)
            .collect()
    }

    /// Create peering request
    pub fn create_request(
        &mut self,
        peer: &PeerNetwork,
        port: &IxpPort,
        peer_ip: IpAddr,
    ) -> PeeringRequest {
        let request = PeeringRequest {
            id: format!("req-{}-{}", peer.asn, port.ixp_id),
            peer_asn: peer.asn,
            peer_name: peer.name.clone(),
            ixp_id: port.ixp_id,
            ixp_name: port.ixp_name.clone(),
            our_ip: port.ipv4_address.unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
            peer_ip,
            requested_at: chrono::Utc::now().timestamp(),
            status: RequestStatus::Draft,
            contact_email: None,
            notes: None,
        };
        
        self.pending_requests.push(request.clone());
        request
    }

    /// Generate BIRD configuration for a session
    pub fn generate_session_bird_config(&self, session: &PeeringSession) -> String {
        let session_name = format!(
            "peer_as{}_{}", 
            session.peer_asn,
            session.peer_ip.to_string().replace('.', "_").replace(':', "_")
        );
        
        format!(r#"
# Peering Session: {} (AS{})
protocol bgp {} from ixp_peer {{
    neighbor {} as {};
    description "{}";
    
    ipv4 {{
        import limit {} action restart;
        export filter ixp_export;
    }};
}}
"#,
            session.peer_name,
            session.peer_asn,
            session_name,
            session.peer_ip,
            session.peer_asn,
            session.peer_name,
            5000, // Default max prefix
        )
    }

    /// Generate email template for peering request
    pub fn generate_peering_email(&self, request: &PeeringRequest) -> String {
        format!(r#"Subject: Peering Request - AS{} at {}

Dear Peering Team,

We would like to establish a BGP peering session with AS{} ({}) at {}.

Our Details:
- ASN: {}
- Network: OpenSASE
- Peering Policy: Open
- IPv4 Address: {}
- IPv6 Address: Available
- Max Prefixes (v4): 100
- Max Prefixes (v6): 50
- IRR: AS-OPENSASE

We look forward to establishing a mutually beneficial peering relationship.

Best regards,
OpenSASE Network Operations
noc@opensase.io
"#,
            request.peer_asn,
            request.ixp_name,
            request.peer_asn,
            request.peer_name,
            request.ixp_name,
            OPENSASE_ASN,
            request.our_ip,
        )
    }

    /// Calculate session health score
    pub fn session_health_score(&self, session: &PeeringSession) -> f32 {
        let mut score = 0.0;
        
        // State (40%)
        score += match session.state {
            BgpSessionState::Established => 40.0,
            BgpSessionState::OpenConfirm => 30.0,
            BgpSessionState::OpenSent => 20.0,
            _ => 0.0,
        };
        
        // Prefixes received (30%)
        if session.prefixes_received > 0 {
            score += 30.0 * (session.prefixes_received as f32 / 1000.0).min(1.0);
        }
        
        // Uptime (30%)
        let uptime_hours = session.uptime_seconds / 3600;
        score += 30.0 * (uptime_hours as f32 / 168.0).min(1.0); // 1 week max
        
        score
    }

    /// Get session statistics
    pub fn session_stats(&self) -> SessionStats {
        let total = self.sessions.len();
        let established = self.established_sessions().len();
        let total_prefixes: u32 = self.sessions.values()
            .map(|s| s.prefixes_received)
            .sum();
        let unique_asns: std::collections::HashSet<u32> = self.sessions.values()
            .map(|s| s.peer_asn)
            .collect();
        
        SessionStats {
            total_sessions: total,
            established_sessions: established,
            total_prefixes_received: total_prefixes,
            unique_peers: unique_asns.len(),
            avg_health_score: if total > 0 {
                self.sessions.values()
                    .map(|s| self.session_health_score(s))
                    .sum::<f32>() / total as f32
            } else {
                0.0
            },
        }
    }

    /// Find candidate peers to request peering with
    pub fn find_peering_candidates(&self, available_peers: &[PeerNetwork]) -> Vec<&PeerNetwork> {
        let existing_asns: std::collections::HashSet<u32> = self.sessions.values()
            .map(|s| s.peer_asn)
            .collect();
        
        available_peers.iter()
            .filter(|p| !existing_asns.contains(&p.asn))
            .filter(|p| p.peering_policy == PeeringPolicy::Open)
            .collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub established_sessions: usize,
    pub total_prefixes_received: u32,
    pub unique_peers: usize,
    pub avg_health_score: f32,
}

/// Priority peers (major networks to peer with)
pub fn get_priority_peers() -> Vec<(u32, &'static str, &'static str)> {
    vec![
        // Tier 1 Transit / Major CDNs
        (13335, "Cloudflare", "Content"),
        (15169, "Google", "Content"),
        (32934, "Facebook", "Content"),
        (16509, "Amazon", "Content"),
        (8075, "Microsoft", "Content"),
        (20940, "Akamai", "Content"),
        (54113, "Fastly", "Content"),
        
        // Major ISPs
        (7922, "Comcast", "ISP"),
        (7018, "AT&T", "ISP"),
        (701, "Verizon", "ISP"),
        (3356, "Lumen (Level3)", "Tier1"),
        (1299, "Telia", "Tier1"),
        (174, "Cogent", "Tier1"),
        (6939, "Hurricane Electric", "Tier1"),
        
        // Regional ISPs
        (6830, "Liberty Global", "Cable"),
        (5089, "Virgin Media", "Cable"),
        (12322, "Free (France)", "ISP"),
        (3320, "Deutsche Telekom", "ISP"),
        (6805, "Telefonica", "ISP"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();
        
        manager.add_session(PeeringSession {
            id: "sess-1".to_string(),
            ixp_port_id: "port-1".to_string(),
            peer_asn: 13335,
            peer_name: "Cloudflare".to_string(),
            peer_ip: "80.81.192.1".parse().unwrap(),
            local_ip: "80.81.192.100".parse().unwrap(),
            peering_type: PeeringType::Bilateral,
            state: BgpSessionState::Established,
            prefixes_received: 5000,
            prefixes_sent: 50,
            uptime_seconds: 86400 * 7,
            last_state_change: 0,
        });
        
        let stats = manager.session_stats();
        assert_eq!(stats.total_sessions, 1);
        assert_eq!(stats.established_sessions, 1);
    }

    #[test]
    fn test_health_score() {
        let manager = SessionManager::new();
        
        let healthy_session = PeeringSession {
            id: "test".to_string(),
            ixp_port_id: "port-1".to_string(),
            peer_asn: 13335,
            peer_name: "Test".to_string(),
            peer_ip: "10.0.0.1".parse().unwrap(),
            local_ip: "10.0.0.2".parse().unwrap(),
            peering_type: PeeringType::Bilateral,
            state: BgpSessionState::Established,
            prefixes_received: 1000,
            prefixes_sent: 10,
            uptime_seconds: 86400 * 7,
            last_state_change: 0,
        };
        
        let score = manager.session_health_score(&healthy_session);
        assert!(score > 90.0);
    }
}
