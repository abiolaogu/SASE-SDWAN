//! AuthZ Filter - Policy-Based Authorization
//!
//! Integrates with external policy engine for fine-grained access control.

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

proxy_wasm::main! {{
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(AuthzFilterRoot::new())
    });
}}

/// Permission level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    None,
    Read,
    Write,
    Admin,
}

/// Resource policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePolicy {
    /// Path pattern (glob)
    pub path: String,
    
    /// Required permission
    pub required_permission: Permission,
    
    /// Allowed methods
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    
    /// Required groups
    #[serde(default)]
    pub required_groups: Vec<String>,
    
    /// Required MFA
    #[serde(default)]
    pub require_mfa: bool,
    
    /// Time-based access (allowed hours)
    #[serde(default)]
    pub allowed_hours: Option<(u8, u8)>,
}

/// User context from JWT
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserContext {
    pub user_id: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub permissions: HashMap<String, Permission>,
    pub mfa_verified: bool,
    pub tenant_id: Option<String>,
    pub device_id: Option<String>,
    pub device_posture: Option<String>,
}

/// AuthZ filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzFilterConfig {
    /// Enable authorization
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Policy engine URL (for external checks)
    #[serde(default)]
    pub policy_engine_url: Option<String>,
    
    /// Policy engine cluster
    #[serde(default = "default_cluster")]
    pub policy_engine_cluster: String,
    
    /// Cache TTL seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,
    
    /// Default deny if no policy matches
    #[serde(default = "default_true")]
    pub default_deny: bool,
    
    /// Resource policies (inline)
    #[serde(default)]
    pub policies: Vec<ResourcePolicy>,
    
    /// Skip paths (health checks, etc)
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

fn default_true() -> bool { true }
fn default_cluster() -> String { "policy_engine_cluster".to_string() }
fn default_cache_ttl() -> u64 { 300 }

impl Default for AuthzFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            policy_engine_url: None,
            policy_engine_cluster: "policy_engine_cluster".to_string(),
            cache_ttl_seconds: 300,
            default_deny: true,
            policies: vec![
                // Default admin policy
                ResourcePolicy {
                    path: "/admin/*".to_string(),
                    required_permission: Permission::Admin,
                    allowed_methods: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
                    required_groups: vec!["admin".to_string()],
                    require_mfa: true,
                    allowed_hours: Some((9, 17)), // 9 AM to 5 PM
                },
                // API write policy
                ResourcePolicy {
                    path: "/api/*".to_string(),
                    required_permission: Permission::Write,
                    allowed_methods: vec!["POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
                    required_groups: vec![],
                    require_mfa: false,
                    allowed_hours: None,
                },
                // API read policy
                ResourcePolicy {
                    path: "/api/*".to_string(),
                    required_permission: Permission::Read,
                    allowed_methods: vec!["GET".to_string()],
                    required_groups: vec![],
                    require_mfa: false,
                    allowed_hours: None,
                },
            ],
            skip_paths: vec![
                "/health".to_string(),
                "/ready".to_string(),
                "/metrics".to_string(),
                "/.well-known/*".to_string(),
            ],
        }
    }
}

/// Root context for AuthZ filter
pub struct AuthzFilterRoot {
    config: AuthzFilterConfig,
}

impl AuthzFilterRoot {
    fn new() -> Self {
        Self {
            config: AuthzFilterConfig::default(),
        }
    }
}

impl Context for AuthzFilterRoot {}

impl RootContext for AuthzFilterRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(config) = serde_json::from_slice::<AuthzFilterConfig>(&config_bytes) {
                self.config = config;
                log::info!(
                    "AuthZ filter configured: {} policies, default_deny={}",
                    self.config.policies.len(),
                    self.config.default_deny
                );
            }
        }
        true
    }
    
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(AuthzFilter {
            config: self.config.clone(),
            user_context: None,
        }))
    }
    
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// HTTP context for AuthZ filter
pub struct AuthzFilter {
    config: AuthzFilterConfig,
    user_context: Option<UserContext>,
}

impl AuthzFilter {
    /// Extract user context from JWT payload header
    fn extract_user_context(&self, jwt_payload: &str) -> Option<UserContext> {
        // JWT payload is base64 encoded JSON
        if let Ok(decoded) = base64_decode(jwt_payload) {
            if let Ok(ctx) = serde_json::from_slice::<UserContext>(&decoded) {
                return Some(ctx);
            }
        }
        None
    }
    
    /// Check if path should be skipped
    fn should_skip(&self, path: &str) -> bool {
        for skip_path in &self.config.skip_paths {
            if path_matches(path, skip_path) {
                return true;
            }
        }
        false
    }
    
    /// Find matching policy
    fn find_policy(&self, path: &str, method: &str) -> Option<&ResourcePolicy> {
        for policy in &self.config.policies {
            if path_matches(path, &policy.path) {
                if policy.allowed_methods.is_empty() || 
                   policy.allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
                    return Some(policy);
                }
            }
        }
        None
    }
    
    /// Check authorization
    fn check_authorization(&self, user: &UserContext, policy: &ResourcePolicy) -> AuthzResult {
        // Check required groups
        if !policy.required_groups.is_empty() {
            let has_group = policy.required_groups.iter()
                .any(|g| user.groups.contains(g));
            if !has_group {
                return AuthzResult::Denied("Insufficient group membership".to_string());
            }
        }
        
        // Check MFA requirement
        if policy.require_mfa && !user.mfa_verified {
            return AuthzResult::MfaRequired;
        }
        
        // Check permission level
        let user_permission = user.permissions.get("default")
            .cloned()
            .unwrap_or(Permission::Read);
        
        if user_permission < policy.required_permission {
            return AuthzResult::Denied(format!(
                "Insufficient permission: have {:?}, need {:?}",
                user_permission, policy.required_permission
            ));
        }
        
        // Check time-based access
        if let Some((start, end)) = policy.allowed_hours {
            // In production, would get current hour
            let current_hour = 12u8; // Placeholder
            if current_hour < start || current_hour >= end {
                return AuthzResult::Denied("Access not allowed at this time".to_string());
            }
        }
        
        AuthzResult::Allowed
    }
}

/// Authorization result
enum AuthzResult {
    Allowed,
    Denied(String),
    MfaRequired,
}

impl Context for AuthzFilter {}

impl HttpContext for AuthzFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if !self.config.enabled {
            return Action::Continue;
        }
        
        // Get request path and method
        let path = self.get_http_request_header(":path")
            .unwrap_or_default();
        let method = self.get_http_request_header(":method")
            .unwrap_or_default();
        
        // Skip health checks etc
        if self.should_skip(&path) {
            return Action::Continue;
        }
        
        // Extract user context from JWT
        let user_context = if let Some(jwt_payload) = self.get_http_request_header("x-jwt-payload") {
            self.extract_user_context(&jwt_payload)
        } else {
            None
        };
        
        let user = match user_context {
            Some(u) => u,
            None => {
                if self.config.default_deny {
                    log::warn!("AuthZ: No user context, denying {}", path);
                    self.send_http_response(
                        401,
                        vec![("content-type", "application/json")],
                        Some(br#"{"error":"unauthorized","message":"Authentication required"}"#),
                    );
                    return Action::Pause;
                }
                return Action::Continue;
            }
        };
        
        // Find matching policy
        let policy = match self.find_policy(&path, &method) {
            Some(p) => p,
            None => {
                if self.config.default_deny {
                    log::warn!("AuthZ: No policy for {} {}, denying", method, path);
                    self.send_http_response(
                        403,
                        vec![("content-type", "application/json")],
                        Some(br#"{"error":"forbidden","message":"No policy found for this resource"}"#),
                    );
                    return Action::Pause;
                }
                return Action::Continue;
            }
        };
        
        // Check authorization
        match self.check_authorization(&user, policy) {
            AuthzResult::Allowed => {
                self.set_http_request_header("x-authz-result", Some("allowed"));
                self.set_http_request_header("x-authz-user", Some(&user.user_id));
                Action::Continue
            }
            AuthzResult::Denied(reason) => {
                log::warn!(
                    "AuthZ: Denied {} {} for user {} - {}",
                    method, path, user.user_id, reason
                );
                self.send_http_response(
                    403,
                    vec![("content-type", "application/json")],
                    Some(format!(
                        r#"{{"error":"forbidden","message":"{}"}}"#, 
                        reason
                    ).as_bytes()),
                );
                Action::Pause
            }
            AuthzResult::MfaRequired => {
                log::info!(
                    "AuthZ: MFA required for {} {} user {}",
                    method, path, user.user_id
                );
                self.send_http_response(
                    401,
                    vec![
                        ("content-type", "application/json"),
                        ("x-mfa-required", "true"),
                    ],
                    Some(br#"{"error":"mfa_required","message":"Multi-factor authentication required"}"#),
                );
                Action::Pause
            }
        }
    }
}

/// Simple glob-style path matching
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        path.starts_with(prefix)
    } else if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

/// Simple base64 decode
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    // Simplified base64 decode - in production use proper library
    let mut output = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    
    for chunk in chars.chunks(4) {
        let mut buf = 0u32;
        let mut valid = 0;
        
        for (i, &c) in chunk.iter().enumerate() {
            let val = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '+' => 62,
                '/' => 63,
                '=' => continue,
                _ => return Err(()),
            };
            buf |= val << (18 - 6 * i);
            valid = i + 1;
        }
        
        if valid >= 2 { output.push((buf >> 16) as u8); }
        if valid >= 3 { output.push((buf >> 8) as u8); }
        if valid >= 4 { output.push(buf as u8); }
    }
    
    Ok(output)
}
