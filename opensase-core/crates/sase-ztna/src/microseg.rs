//! Micro-Segmentation Engine
//!
//! Network micro-segmentation for zero trust.

use crate::{AccessRequest, Identity, Resource, ResourceType};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Micro-segmentation engine
pub struct MicroSegmentationEngine {
    /// Network segments
    segments: dashmap::DashMap<String, NetworkSegment>,
    /// Segment policies
    segment_policies: dashmap::DashMap<String, SegmentPolicy>,
    /// Application connectors
    connectors: dashmap::DashMap<String, AppConnector>,
}

#[derive(Debug, Clone)]
pub struct NetworkSegment {
    pub id: String,
    pub name: String,
    pub cidr: String,
    pub tags: HashMap<String, String>,
    pub trust_level: SegmentTrust,
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentTrust {
    Untrusted,
    External,
    DMZ,
    Internal,
    Sensitive,
    Restricted,
}

#[derive(Debug, Clone)]
pub struct SegmentPolicy {
    pub id: String,
    pub name: String,
    pub source_segment: String,
    pub destination_segment: String,
    pub allowed_protocols: Vec<Protocol>,
    pub allowed_ports: Vec<PortRange>,
    pub conditions: Vec<SegmentCondition>,
    pub action: SegmentAction,
}

#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
    Http,
    Https,
    Ssh,
    Rdp,
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub enum SegmentCondition {
    HasRole(String),
    InGroup(String),
    FromApprovedDevice,
    DuringWorkHours,
    MfaVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentAction {
    Allow,
    Deny,
    Inspect,
    Log,
}

#[derive(Debug, Clone)]
pub struct AppConnector {
    pub id: String,
    pub name: String,
    pub connector_type: ConnectorType,
    pub target: ConnectorTarget,
    pub health: ConnectorHealth,
    pub routing: ConnectorRouting,
}

#[derive(Debug, Clone)]
pub enum ConnectorType {
    Agent,       // Installed agent on-prem
    CloudNative, // Cloud-native connector
    Tunnel,      // VPN tunnel
    Proxy,       // HTTP proxy
}

#[derive(Debug, Clone)]
pub struct ConnectorTarget {
    pub address: String,
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy)]
pub enum ConnectorHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum ConnectorRouting {
    Direct,
    ViaGateway(String),
    LoadBalanced(Vec<String>),
}

impl MicroSegmentationEngine {
    pub fn new() -> Self {
        let engine = Self {
            segments: dashmap::DashMap::new(),
            segment_policies: dashmap::DashMap::new(),
            connectors: dashmap::DashMap::new(),
        };
        
        // Create default segments
        engine.create_default_segments();
        
        engine
    }
    
    fn create_default_segments(&self) {
        // Internet/untrusted segment
        self.add_segment(NetworkSegment {
            id: "untrusted".to_string(),
            name: "Internet".to_string(),
            cidr: "0.0.0.0/0".to_string(),
            tags: HashMap::new(),
            trust_level: SegmentTrust::Untrusted,
            resources: vec![],
        });
        
        // Internal segment
        self.add_segment(NetworkSegment {
            id: "internal".to_string(),
            name: "Internal Network".to_string(),
            cidr: "10.0.0.0/8".to_string(),
            tags: HashMap::new(),
            trust_level: SegmentTrust::Internal,
            resources: vec![],
        });
        
        // Sensitive data segment
        self.add_segment(NetworkSegment {
            id: "sensitive".to_string(),
            name: "Sensitive Data".to_string(),
            cidr: "10.100.0.0/16".to_string(),
            tags: HashMap::new(),
            trust_level: SegmentTrust::Sensitive,
            resources: vec![],
        });
        
        // Default deny between untrusted and internal
        self.add_policy(SegmentPolicy {
            id: "deny-untrusted-internal".to_string(),
            name: "Deny Untrusted to Internal".to_string(),
            source_segment: "untrusted".to_string(),
            destination_segment: "internal".to_string(),
            allowed_protocols: vec![],
            allowed_ports: vec![],
            conditions: vec![],
            action: SegmentAction::Deny,
        });
        
        // Allow internal to sensitive with MFA
        self.add_policy(SegmentPolicy {
            id: "internal-to-sensitive".to_string(),
            name: "Internal to Sensitive (MFA Required)".to_string(),
            source_segment: "internal".to_string(),
            destination_segment: "sensitive".to_string(),
            allowed_protocols: vec![Protocol::Https],
            allowed_ports: vec![PortRange { start: 443, end: 443 }],
            conditions: vec![
                SegmentCondition::MfaVerified,
                SegmentCondition::FromApprovedDevice,
            ],
            action: SegmentAction::Allow,
        });
    }
    
    /// Check if access is allowed by segmentation
    pub async fn is_allowed(&self, request: &AccessRequest) -> bool {
        // Determine source and destination segments
        let source_segment = self.get_segment_for_ip(&request.context.client_ip);
        let dest_segment = self.get_segment_for_resource(&request.resource);
        
        let source_id = source_segment.map(|s| s.id.clone()).unwrap_or("untrusted".to_string());
        let dest_id = dest_segment.map(|s| s.id.clone()).unwrap_or("internal".to_string());
        
        // Find matching policies
        for policy in self.segment_policies.iter() {
            if policy.source_segment == source_id && policy.destination_segment == dest_id {
                if self.evaluate_policy(&policy, request) {
                    return policy.action == SegmentAction::Allow;
                }
            }
        }
        
        // Default deny
        false
    }
    
    fn get_segment_for_ip(&self, ip: &IpAddr) -> Option<dashmap::mapref::one::Ref<String, NetworkSegment>> {
        for segment in self.segments.iter() {
            if let Ok(network) = segment.cidr.parse::<ipnetwork::IpNetwork>() {
                if network.contains(*ip) {
                    return Some(segment);
                }
            }
        }
        None
    }
    
    fn get_segment_for_resource(&self, resource: &Resource) -> Option<dashmap::mapref::one::Ref<String, NetworkSegment>> {
        for segment in self.segments.iter() {
            if segment.resources.contains(&resource.id) {
                return Some(segment);
            }
        }
        None
    }
    
    fn evaluate_policy(&self, policy: &SegmentPolicy, request: &AccessRequest) -> bool {
        for condition in &policy.conditions {
            match condition {
                SegmentCondition::HasRole(role) => {
                    if !request.identity.roles.contains(role) {
                        return false;
                    }
                }
                SegmentCondition::InGroup(group) => {
                    if !request.identity.groups.contains(group) {
                        return false;
                    }
                }
                SegmentCondition::FromApprovedDevice => {
                    if !request.device.managed || !request.device.compliant {
                        return false;
                    }
                }
                SegmentCondition::DuringWorkHours => {
                    let hour = request.context.time_of_access.time().hour();
                    if hour < 8 || hour > 18 {
                        return false;
                    }
                }
                SegmentCondition::MfaVerified => {
                    if !request.identity.mfa_verified {
                        return false;
                    }
                }
            }
        }
        true
    }
    
    /// Add segment
    pub fn add_segment(&self, segment: NetworkSegment) {
        self.segments.insert(segment.id.clone(), segment);
    }
    
    /// Add policy
    pub fn add_policy(&self, policy: SegmentPolicy) {
        self.segment_policies.insert(policy.id.clone(), policy);
    }
    
    /// Register app connector
    pub fn register_connector(&self, connector: AppConnector) {
        self.connectors.insert(connector.id.clone(), connector);
    }
    
    /// Get route to resource
    pub fn get_route(&self, resource_id: &str) -> Option<RouteInfo> {
        // Find connector for resource
        for connector in self.connectors.iter() {
            // In production: match resource to connector
            return Some(RouteInfo {
                connector_id: connector.id.clone(),
                target: connector.target.clone(),
                routing: connector.routing.clone(),
            });
        }
        None
    }
}

impl Default for MicroSegmentationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub connector_id: String,
    pub target: ConnectorTarget,
    pub routing: ConnectorRouting,
}

use chrono::Timelike;
