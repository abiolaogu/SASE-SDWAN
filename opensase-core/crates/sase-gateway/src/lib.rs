//! OpenSASE Unified API Gateway
//!
//! High-performance gateway integrating all SASE components:
//! - Policy Engine (<1μs decisions)
//! - DLP Scanner (10GB/s throughput)
//! - Path Selector (<5μs recommendations)
//! - ML Inference (behavioral analytics)

#![warn(missing_docs)]

pub mod router;
pub mod handlers;
pub mod middleware;

use axum::{Router, routing::get, routing::post, Extension};
use sase_policy::PolicyEngine;
use sase_dlp::DLPScanner;
use sase_path::{PathSelector, probes::ProbeCollector};
use sase_ml::{PathPredictor, AnomalyDetector};
use std::sync::Arc;
use std::net::SocketAddr;

/// Application state shared across handlers
pub struct AppState {
    /// Policy engine
    pub policy: Arc<PolicyEngine>,
    /// DLP scanner
    pub dlp: Arc<DLPScanner>,
    /// Path selector
    pub path_selector: Arc<PathSelector>,
    /// Path predictor
    pub predictor: Arc<PathPredictor>,
    /// Anomaly detector
    pub anomaly: Arc<AnomalyDetector>,
}

impl AppState {
    /// Create new application state with default configuration
    pub fn new() -> Self {
        let probes = Arc::new(ProbeCollector::default());
        
        Self {
            policy: Arc::new(PolicyEngine::new()),
            dlp: Arc::new(DLPScanner::default_classifiers()),
            path_selector: Arc::new(PathSelector::new(probes)),
            predictor: Arc::new(PathPredictor::default()),
            anomaly: Arc::new(AnomalyDetector::default()),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the API router
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health check
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        
        // Metrics
        .route("/metrics", get(handlers::metrics))
        
        // Policy API
        .route("/api/v1/policy/lookup", post(handlers::policy_lookup))
        .route("/api/v1/policy/stats", get(handlers::policy_stats))
        
        // DLP API
        .route("/api/v1/dlp/scan", post(handlers::dlp_scan))
        .route("/api/v1/dlp/classifiers", get(handlers::dlp_classifiers))
        
        // Path API
        .route("/api/v1/path/recommend", post(handlers::path_recommend))
        .route("/api/v1/path/probes", post(handlers::path_record_probe))
        
        // ML API
        .route("/api/v1/ml/predict", post(handlers::ml_predict))
        .route("/api/v1/ml/risk", post(handlers::ml_risk_score))
        
        // Add state
        .layer(Extension(state))
}

/// Start the gateway server
pub async fn serve(addr: SocketAddr) -> Result<(), std::io::Error> {
    let state = Arc::new(AppState::new());
    let app = build_router(state);

    tracing::info!("OpenSASE Gateway listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state() {
        let state = AppState::new();
        assert_eq!(state.policy.store().len(), 0);
    }
}
