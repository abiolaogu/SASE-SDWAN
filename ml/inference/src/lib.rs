//! OpenSASE Threat Intelligence Engine (OSTIE)
//!
//! ML-powered threat detection for advanced attacks.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    THREAT INTELLIGENCE ENGINE                           │
//! │                                                                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │     DNS      │  │   Network    │  │     UBA      │  │   Malware   │ │
//! │  │  Detection   │  │   Anomaly    │  │   Behavior   │  │   Traffic   │ │
//! │  │  (RF+CNN)    │  │   (IF+AE)    │  │   (LSTM)     │  │   (GBT)     │ │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
//! │         │                 │                 │                 │        │
//! │  ┌──────▼─────────────────▼─────────────────▼─────────────────▼──────┐ │
//! │  │                    INFERENCE ENGINE                               │ │
//! │  │              < 1ms latency, 10K flows/sec/core                   │ │
//! │  └───────────────────────────────────────────────────────────────────┘ │
//! │                                │                                        │
//! │  ┌─────────────────────────────▼─────────────────────────────────────┐ │
//! │  │                    ALERT GENERATION                               │ │
//! │  │   Dedup | Correlation | Enrichment | MITRE ATT&CK Mapping        │ │
//! │  └───────────────────────────────────────────────────────────────────┘ │
//! │                                │                                        │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
//! │  │   Threat     │  │   Feedback   │  │   Hunting    │                  │
//! │  │   Intel      │  │   Loop       │  │  Interface   │                  │
//! │  │  (STIX/TAXII)│  │ (Retraining) │  │              │                  │
//! │  └──────────────┘  └──────────────┘  └──────────────┘                  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod features;
pub mod models;
pub mod inference;
pub mod alerts;
pub mod intel;
pub mod hunting;
pub mod feedback;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;

pub use features::*;
pub use models::*;
pub use inference::InferenceEngine;
pub use alerts::{ThreatAlert, AlertManager};

/// OSTIE error types
#[derive(Debug, Error)]
pub enum OstieError {
    #[error("model error: {0}")]
    Model(String),
    #[error("inference error: {0}")]
    Inference(String),
    #[error("feature extraction error: {0}")]
    Feature(String),
}

/// Main Threat Intelligence Engine
pub struct ThreatEngine {
    /// DNS threat detector
    pub dns_detector: Arc<models::DnsThreatDetector>,
    /// Network anomaly detector
    pub network_detector: Arc<models::NetworkAnomalyDetector>,
    /// User behavior analytics
    pub uba_detector: Arc<models::UbaDetector>,
    /// Malware traffic detector
    pub malware_detector: Arc<models::MalwareDetector>,
    /// Alert manager
    pub alerts: Arc<AlertManager>,
    /// Inference engine
    pub inference: Arc<InferenceEngine>,
}

impl ThreatEngine {
    /// Create new threat engine
    pub fn new() -> Self {
        Self {
            dns_detector: Arc::new(models::DnsThreatDetector::new()),
            network_detector: Arc::new(models::NetworkAnomalyDetector::new()),
            uba_detector: Arc::new(models::UbaDetector::new()),
            malware_detector: Arc::new(models::MalwareDetector::new()),
            alerts: Arc::new(AlertManager::new()),
            inference: Arc::new(InferenceEngine::new()),
        }
    }

    /// Analyze DNS query
    pub async fn analyze_dns(&self, query: &DnsQuery) -> Option<ThreatAlert> {
        let features = self.dns_detector.extract_features(query);
        let result = self.dns_detector.predict(&features);
        
        if result.is_threat {
            Some(self.alerts.create_alert(
                alerts::Severity::High,
                alerts::ThreatCategory::DnsThreat,
                result.confidence,
                result.explanation,
            ))
        } else {
            None
        }
    }

    /// Analyze network flow
    pub async fn analyze_flow(&self, flow: &FlowFeatures) -> Option<ThreatAlert> {
        let result = self.network_detector.predict(flow);
        
        if result.anomaly_score > 0.8 {
            Some(self.alerts.create_alert(
                alerts::Severity::Medium,
                alerts::ThreatCategory::NetworkAnomaly,
                result.anomaly_score,
                result.explanation,
            ))
        } else {
            None
        }
    }

    /// Analyze user session
    pub async fn analyze_session(&self, session: &UserSession) -> Option<ThreatAlert> {
        let result = self.uba_detector.predict(session);
        
        if result.risk_score > 0.7 {
            Some(self.alerts.create_alert(
                alerts::Severity::High,
                alerts::ThreatCategory::InsiderThreat,
                result.risk_score,
                result.explanation,
            ))
        } else {
            None
        }
    }

    /// Load models
    pub async fn load_models(&self, path: &str) -> Result<(), OstieError> {
        tracing::info!("Loading models from {}", path);
        self.dns_detector.load(&format!("{}/dns", path))?;
        self.network_detector.load(&format!("{}/network", path))?;
        self.uba_detector.load(&format!("{}/uba", path))?;
        self.malware_detector.load(&format!("{}/malware", path))?;
        Ok(())
    }
}

impl Default for ThreatEngine {
    fn default() -> Self { Self::new() }
}
