//! CASB Filter - Cloud Access Security Broker
//!
//! Controls access to SaaS applications and enforces policies.

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

proxy_wasm::main! {{
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CasbFilterRoot::new())
    });
}}

/// SaaS application policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaasPolicy {
    /// Allow access to this app
    #[serde(default = "default_true")]
    pub allowed: bool,
    
    /// Enable DLP for this app
    #[serde(default)]
    pub dlp: bool,
    
    /// Allowed actions
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    
    /// Blocked actions
    #[serde(default)]
    pub blocked_actions: Vec<String>,
    
    /// Require MFA
    #[serde(default)]
    pub require_mfa: bool,
}

fn default_true() -> bool { true }

impl Default for SaasPolicy {
    fn default() -> Self {
        Self {
            allowed: true,
            dlp: false,
            allowed_actions: vec![],
            blocked_actions: vec![],
            require_mfa: false,
        }
    }
}

/// CASB filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasbFilterConfig {
    /// SaaS application policies
    #[serde(default)]
    pub saas_apps: HashMap<String, SaasPolicy>,
    
    /// Default policy for unknown apps
    #[serde(default)]
    pub default_policy: SaasPolicy,
    
    /// Enable shadow IT detection
    #[serde(default)]
    pub detect_shadow_it: bool,
    
    /// Log all SaaS access
    #[serde(default = "default_true")]
    pub log_access: bool,
}

impl Default for CasbFilterConfig {
    fn default() -> Self {
        let mut saas_apps = HashMap::new();
        
        // Default policies for common SaaS apps
        saas_apps.insert("microsoft365".to_string(), SaasPolicy {
            allowed: true,
            dlp: true,
            allowed_actions: vec![],
            blocked_actions: vec!["external_sharing".to_string()],
            require_mfa: false,
        });
        
        saas_apps.insert("google_workspace".to_string(), SaasPolicy {
            allowed: true,
            dlp: true,
            allowed_actions: vec![],
            blocked_actions: vec![],
            require_mfa: false,
        });
        
        saas_apps.insert("salesforce".to_string(), SaasPolicy {
            allowed: true,
            dlp: false,
            allowed_actions: vec![],
            blocked_actions: vec![],
            require_mfa: true,
        });
        
        saas_apps.insert("dropbox".to_string(), SaasPolicy {
            allowed: false,
            dlp: false,
            allowed_actions: vec![],
            blocked_actions: vec![],
            require_mfa: false,
        });
        
        Self {
            saas_apps,
            default_policy: SaasPolicy::default(),
            detect_shadow_it: true,
            log_access: true,
        }
    }
}

/// SaaS app detection patterns
struct SaasDetector {
    patterns: Vec<(String, Vec<String>)>,
}

impl SaasDetector {
    fn new() -> Self {
        Self {
            patterns: vec![
                ("microsoft365".to_string(), vec![
                    "office.com".to_string(),
                    "office365.com".to_string(),
                    "microsoft.com".to_string(),
                    "microsoftonline.com".to_string(),
                    "sharepoint.com".to_string(),
                    "onedrive.com".to_string(),
                    "outlook.com".to_string(),
                ]),
                ("google_workspace".to_string(), vec![
                    "google.com".to_string(),
                    "googleapis.com".to_string(),
                    "gstatic.com".to_string(),
                    "gmail.com".to_string(),
                    "drive.google.com".to_string(),
                ]),
                ("salesforce".to_string(), vec![
                    "salesforce.com".to_string(),
                    "force.com".to_string(),
                    "lightning.force.com".to_string(),
                ]),
                ("dropbox".to_string(), vec![
                    "dropbox.com".to_string(),
                    "dropboxapi.com".to_string(),
                ]),
                ("slack".to_string(), vec![
                    "slack.com".to_string(),
                    "slack-edge.com".to_string(),
                ]),
                ("zoom".to_string(), vec![
                    "zoom.us".to_string(),
                    "zoomgov.com".to_string(),
                ]),
                ("aws".to_string(), vec![
                    "amazonaws.com".to_string(),
                    "aws.amazon.com".to_string(),
                ]),
                ("github".to_string(), vec![
                    "github.com".to_string(),
                    "githubusercontent.com".to_string(),
                ]),
            ],
        }
    }
    
    /// Detect SaaS app from domain
    fn detect(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();
        
        for (app_name, patterns) in &self.patterns {
            for pattern in patterns {
                if domain_lower.ends_with(pattern) || domain_lower == *pattern {
                    return Some(app_name.clone());
                }
            }
        }
        
        None
    }
}

/// Root context for CASB filter
pub struct CasbFilterRoot {
    config: CasbFilterConfig,
    detector: SaasDetector,
}

impl CasbFilterRoot {
    fn new() -> Self {
        Self {
            config: CasbFilterConfig::default(),
            detector: SaasDetector::new(),
        }
    }
}

impl Context for CasbFilterRoot {}

impl RootContext for CasbFilterRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(config) = serde_json::from_slice::<CasbFilterConfig>(&config_bytes) {
                self.config = config;
                log::info!(
                    "CASB filter configured: {} SaaS app policies",
                    self.config.saas_apps.len()
                );
            }
        }
        true
    }
    
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CasbFilter {
            config: self.config.clone(),
            detector: SaasDetector::new(),
        }))
    }
    
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// HTTP context for CASB filter
pub struct CasbFilter {
    config: CasbFilterConfig,
    detector: SaasDetector,
}

impl Context for CasbFilter {}

impl HttpContext for CasbFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Get the host header
        let host = match self.get_http_request_header(":authority") {
            Some(h) => h,
            None => return Action::Continue,
        };
        
        // Remove port if present
        let domain = host.split(':').next().unwrap_or(&host);
        
        // Detect SaaS application
        let app_name = self.detector.detect(domain);
        
        // Get policy
        let policy = if let Some(ref app) = app_name {
            self.config.saas_apps.get(app).unwrap_or(&self.config.default_policy)
        } else {
            // Shadow IT detection
            if self.config.detect_shadow_it {
                self.set_http_request_header("x-casb-shadow-it", Some("true"));
                log::info!("Potential shadow IT: {}", domain);
            }
            &self.config.default_policy
        };
        
        // Set metadata
        if let Some(ref app) = app_name {
            self.set_http_request_header("x-casb-app", Some(app));
        }
        
        // Check if allowed
        if !policy.allowed {
            log::warn!(
                "CASB blocked access to {} (app: {:?})",
                domain,
                app_name
            );
            
            self.send_http_response(
                403,
                vec![("content-type", "text/html")],
                Some(format!(
                    "<html><body><h1>Access Denied</h1>\
                     <p>Access to {} is not allowed by your organization's policy.</p>\
                     <p>Contact your IT administrator for access.</p></body></html>",
                    app_name.as_ref().unwrap_or(&domain.to_string())
                ).as_bytes()),
            );
            return Action::Pause;
        }
        
        // Check MFA requirement
        if policy.require_mfa {
            let has_mfa = self.get_http_request_header("x-mfa-verified")
                .map(|v| v == "true")
                .unwrap_or(false);
            
            if !has_mfa {
                log::warn!("MFA required for {}", domain);
                self.send_http_response(
                    401,
                    vec![
                        ("content-type", "text/html"),
                        ("x-casb-mfa-required", "true"),
                    ],
                    Some(b"<html><body><h1>MFA Required</h1>\
                          <p>Multi-factor authentication is required for this application.</p>\
                          </body></html>"),
                );
                return Action::Pause;
            }
        }
        
        // Log access
        if self.config.log_access {
            log::info!(
                "CASB: {} -> {} (app: {:?}, dlp: {})",
                self.get_http_request_header(":path").unwrap_or_default(),
                domain,
                app_name,
                policy.dlp
            );
        }
        
        // Enable DLP for this request if needed
        if policy.dlp {
            self.set_http_request_header("x-casb-dlp-enabled", Some("true"));
        }
        
        Action::Continue
    }
}
