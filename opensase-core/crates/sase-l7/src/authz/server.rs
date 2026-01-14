//! gRPC AuthZ Policy Engine Server
//!
//! Implements Envoy ext_authz gRPC interface.

use crate::authz::{Policy, PolicyContext, PolicyDecision, PolicyStore, User, UserDirectory};
use crate::Result;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, warn, debug};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Check request from Envoy
#[derive(Debug, Clone)]
pub struct CheckRequest {
    pub path: String,
    pub method: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub source_ip: Option<String>,
}

/// Check response to Envoy
#[derive(Debug, Clone)]
pub enum CheckResponse {
    Allow {
        headers_to_add: Vec<(String, String)>,
    },
    Deny {
        status_code: u32,
        body: String,
    },
    Redirect {
        location: String,
    },
}

/// gRPC Policy Engine
pub struct PolicyEngine {
    /// Policy store
    policy_store: Arc<PolicyStore>,
    
    /// User directory
    user_directory: Arc<UserDirectory>,
    
    /// Request counter
    request_count: std::sync::atomic::AtomicU64,
}

impl PolicyEngine {
    /// Create new policy engine
    pub fn new(policy_store: Arc<PolicyStore>, user_directory: Arc<UserDirectory>) -> Self {
        Self {
            policy_store,
            user_directory,
            request_count: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Check authorization request
    pub async fn check(&self, request: CheckRequest) -> Result<CheckResponse> {
        self.request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        debug!(
            "AuthZ check: {} {} from {:?}",
            request.method, request.path, request.source_ip
        );
        
        // Extract user from JWT headers (already validated by Envoy)
        let user_id = request.headers.get("x-jwt-sub").cloned();
        let user_groups: Vec<String> = request.headers
            .get("x-jwt-groups")
            .map(|g| g.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
        
        // No authenticated user
        let user = match &user_id {
            Some(uid) => {
                match self.user_directory.get_user(uid).await {
                    Ok(Some(u)) => u,
                    Ok(None) => {
                        warn!("User not found: {}", uid);
                        return Ok(self.deny(401, "User not found"));
                    }
                    Err(e) => {
                        warn!("User lookup failed: {}", e);
                        return Ok(self.deny(500, "Internal error"));
                    }
                }
            }
            None => {
                return Ok(self.deny(401, "No authenticated user"));
            }
        };
        
        // Get device posture
        let device_posture = self.get_device_posture(&request.headers).await;
        
        // Build policy context
        let context = PolicyContext {
            user: user.clone(),
            groups: user_groups,
            source_ip: request.source_ip,
            destination: request.host.clone(),
            path: request.path.clone(),
            method: request.method.clone(),
            time: Utc::now(),
            device_posture,
            headers: request.headers.clone(),
        };
        
        // Evaluate policies
        let decision = self.policy_store.evaluate(&context).await;
        
        match decision {
            PolicyDecision::Allow => {
                info!("ALLOW: user={} path={}", user.id, request.path);
                Ok(CheckResponse::Allow {
                    headers_to_add: vec![
                        ("x-opensase-user".to_string(), user.id.clone()),
                        ("x-opensase-tenant".to_string(), user.tenant_id.clone()),
                    ],
                })
            }
            PolicyDecision::Deny(reason) => {
                warn!("DENY: user={} path={} reason={}", user.id, request.path, reason);
                Ok(self.deny(403, &reason))
            }
            PolicyDecision::RequireMFA => {
                info!("MFA_REQUIRED: user={}", user.id);
                Ok(self.redirect_to_mfa(&user))
            }
            PolicyDecision::StepUp(auth_level) => {
                info!("STEPUP_REQUIRED: user={} level={}", user.id, auth_level);
                Ok(self.redirect_to_stepup(&user, &auth_level))
            }
        }
    }
    
    /// Get device posture from headers
    async fn get_device_posture(&self, headers: &HashMap<String, String>) -> Option<DevicePosture> {
        let device_id = headers.get("x-device-id")?;
        let posture_score = headers.get("x-posture-score")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        
        Some(DevicePosture {
            device_id: device_id.clone(),
            score: posture_score,
            compliant: posture_score >= 70,
            os_updated: headers.get("x-os-updated").map(|s| s == "true").unwrap_or(false),
            antivirus_active: headers.get("x-av-active").map(|s| s == "true").unwrap_or(false),
            disk_encrypted: headers.get("x-disk-encrypted").map(|s| s == "true").unwrap_or(false),
        })
    }
    
    /// Create deny response
    fn deny(&self, status_code: u32, reason: &str) -> CheckResponse {
        CheckResponse::Deny {
            status_code,
            body: format!(r#"{{"error": "{}"}}"#, reason),
        }
    }
    
    /// Redirect to MFA
    fn redirect_to_mfa(&self, user: &User) -> CheckResponse {
        CheckResponse::Redirect {
            location: format!(
                "https://auth.opensase.io/mfa?user={}&redirect={}",
                urlencoding::encode(&user.id),
                urlencoding::encode("https://app.opensase.io/continue")
            ),
        }
    }
    
    /// Redirect to step-up auth
    fn redirect_to_stepup(&self, user: &User, level: &str) -> CheckResponse {
        CheckResponse::Redirect {
            location: format!(
                "https://auth.opensase.io/stepup?user={}&level={}&redirect={}",
                urlencoding::encode(&user.id),
                urlencoding::encode(level),
                urlencoding::encode("https://app.opensase.io/continue")
            ),
        }
    }
    
    /// Get request count
    pub fn request_count(&self) -> u64 {
        self.request_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Device posture information
#[derive(Debug, Clone)]
pub struct DevicePosture {
    pub device_id: String,
    pub score: u32,
    pub compliant: bool,
    pub os_updated: bool,
    pub antivirus_active: bool,
    pub disk_encrypted: bool,
}

/// Start gRPC server
pub async fn start_grpc_server(
    addr: &str,
    policy_store: Arc<PolicyStore>,
    user_directory: Arc<UserDirectory>,
) -> Result<()> {
    let engine = PolicyEngine::new(policy_store, user_directory);
    
    info!("Starting AuthZ gRPC server on {}", addr);
    
    // In production, would use tonic::transport::Server
    // with proper ext_authz protobuf definitions
    
    Ok(())
}
