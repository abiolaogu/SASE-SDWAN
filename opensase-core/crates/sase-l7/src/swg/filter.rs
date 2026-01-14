//! URL Filter Service - Secure Web Gateway
//!
//! High-performance URL filtering with bloom filter and category lookup.

use crate::swg::{Category, CategoryDatabase, BlocklistManager};
use crate::authz::PolicyStore;
use crate::Result;
use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn, debug};

/// URL check request
#[derive(Debug, Clone, Deserialize)]
pub struct UrlCheckRequest {
    /// Host/domain
    pub host: String,
    
    /// Full URL
    pub url: String,
    
    /// User ID
    pub user_id: Option<String>,
    
    /// User groups
    #[serde(default)]
    pub groups: Vec<String>,
    
    /// Tenant ID
    pub tenant_id: Option<String>,
}

/// URL check response
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action")]
pub enum UrlCheckResponse {
    /// Allow access
    #[serde(rename = "allow")]
    Allow {
        category: String,
    },
    
    /// Block access
    #[serde(rename = "block")]
    Block {
        reason: String,
        category: String,
    },
    
    /// Warn user
    #[serde(rename = "warn")]
    Warn {
        message: String,
        continue_url: String,
    },
    
    /// Redirect to browser isolation
    #[serde(rename = "isolate")]
    Isolate {
        isolation_url: String,
    },
}

/// URL policy result
#[derive(Debug, Clone)]
pub enum UrlPolicy {
    Allow,
    Block(String),
    Warn,
    Isolate,
}

/// URL Filter Service
pub struct UrlFilterService {
    /// Blocklist manager
    blocklist: Arc<BlocklistManager>,
    
    /// Category database
    category_db: Arc<CategoryDatabase>,
    
    /// Policy store
    policy_store: Arc<PolicyStore>,
    
    /// Request counter
    request_count: std::sync::atomic::AtomicU64,
}

impl UrlFilterService {
    /// Create new URL filter service
    pub fn new(
        blocklist: Arc<BlocklistManager>,
        category_db: Arc<CategoryDatabase>,
        policy_store: Arc<PolicyStore>,
    ) -> Self {
        Self {
            blocklist,
            category_db,
            policy_store,
            request_count: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Check URL
    pub async fn check_url(&self, request: UrlCheckRequest) -> UrlCheckResponse {
        self.request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        let domain = extract_domain(&request.host);
        debug!("Checking URL: {} (domain: {})", request.url, domain);
        
        // 1. Fast bloom filter check for known-bad domains
        if self.blocklist.probably_blocked(&domain) {
            // Confirm with exact lookup (bloom filters have false positives)
            if let Some(reason) = self.blocklist.is_blocked_exact(&domain).await {
                warn!("Blocked domain: {} - {}", domain, reason);
                return UrlCheckResponse::Block {
                    reason: reason.clone(),
                    category: "blocked".to_string(),
                };
            }
        }
        
        // 2. Category lookup
        let category = self.category_db.lookup(&domain).await
            .unwrap_or(Category::Unknown);
        
        // 3. Check blocked categories
        if self.is_blocked_category(&category) {
            warn!("Blocked category: {} for {}", category.as_str(), domain);
            return UrlCheckResponse::Block {
                reason: format!("Category '{}' is blocked by policy", category.as_str()),
                category: category.as_str().to_string(),
            };
        }
        
        // 4. Check if isolation required
        if self.should_isolate(&category, &request.groups) {
            info!("Isolating: {} (category: {})", domain, category.as_str());
            return UrlCheckResponse::Isolate {
                isolation_url: format!(
                    "https://rbi.opensase.io/browse?url={}",
                    urlencoding::encode(&request.url)
                ),
            };
        }
        
        // 5. Check if warning required
        if self.should_warn(&category) {
            return UrlCheckResponse::Warn {
                message: format!("This site is categorized as: {}", category.as_str()),
                continue_url: request.url,
            };
        }
        
        // Allow
        UrlCheckResponse::Allow {
            category: category.as_str().to_string(),
        }
    }
    
    /// Check if category is blocked
    fn is_blocked_category(&self, category: &Category) -> bool {
        matches!(
            category,
            Category::Malware 
            | Category::Phishing 
            | Category::Gambling 
            | Category::Adult 
            | Category::Weapons
            | Category::Hacking
        )
    }
    
    /// Check if should isolate
    fn should_isolate(&self, category: &Category, groups: &[String]) -> bool {
        // Isolate risky categories for non-admin users
        if groups.contains(&"admin".to_string()) {
            return false;
        }
        
        matches!(
            category,
            Category::FileSharing | Category::Proxy
        )
    }
    
    /// Check if should warn
    fn should_warn(&self, category: &Category) -> bool {
        matches!(
            category,
            Category::SocialMedia | Category::Streaming | Category::Gaming
        )
    }
    
    /// Get request count
    pub fn request_count(&self) -> u64 {
        self.request_count.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    /// Create Axum router
    pub fn router(service: Arc<Self>) -> Router {
        Router::new()
            .route("/check", post(check_url_handler))
            .route("/health", get(health_handler))
            .route("/stats", get(stats_handler))
            .with_state(service)
    }
}

/// Extract domain from host
fn extract_domain(host: &str) -> String {
    // Remove port if present
    let domain = host.split(':').next().unwrap_or(host);
    domain.to_lowercase()
}

/// Check URL handler
async fn check_url_handler(
    State(service): State<Arc<UrlFilterService>>,
    Json(request): Json<UrlCheckRequest>,
) -> Json<UrlCheckResponse> {
    Json(service.check_url(request).await)
}

/// Health handler
async fn health_handler() -> &'static str {
    "OK"
}

/// Stats handler
async fn stats_handler(
    State(service): State<Arc<UrlFilterService>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "requests_processed": service.request_count(),
        "status": "healthy"
    }))
}

/// Start URL filter HTTP server
pub async fn start_http_server(addr: &str, service: Arc<UrlFilterService>) -> Result<()> {
    let app = UrlFilterService::router(service);
    
    info!("Starting URL filter HTTP server on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
