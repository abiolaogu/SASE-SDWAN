//! Inference Engine

use crate::{OstieError, features::*, models::*};
use std::sync::Arc;
use std::time::Instant;
use parking_lot::RwLock;

/// Real-time inference engine
pub struct InferenceEngine {
    /// DNS detector
    dns: Arc<DnsThreatDetector>,
    /// Network detector
    network: Arc<NetworkAnomalyDetector>,
    /// UBA detector
    uba: Arc<UbaDetector>,
    /// Malware detector
    malware: Arc<MalwareDetector>,
    /// Stats
    stats: Arc<RwLock<InferenceStats>>,
}

impl InferenceEngine {
    pub fn new() -> Self {
        Self {
            dns: Arc::new(DnsThreatDetector::new()),
            network: Arc::new(NetworkAnomalyDetector::new()),
            uba: Arc::new(UbaDetector::new()),
            malware: Arc::new(MalwareDetector::new()),
            stats: Arc::new(RwLock::new(InferenceStats::default())),
        }
    }

    /// Batch inference on flows
    pub fn infer_batch(&self, flows: &[FlowFeatures]) -> Vec<NetworkPrediction> {
        let start = Instant::now();
        
        let results: Vec<_> = flows.iter()
            .map(|f| self.network.predict(f))
            .collect();
        
        let elapsed = start.elapsed();
        let mut stats = self.stats.write();
        stats.total_inferences += results.len() as u64;
        stats.total_latency_us += elapsed.as_micros() as u64;
        
        results
    }

    /// Single DNS inference
    pub fn infer_dns(&self, query: &DnsQuery) -> DnsPrediction {
        let start = Instant::now();
        
        let features = self.dns.extract_features(query);
        let result = self.dns.predict(&features);
        
        let elapsed = start.elapsed();
        let mut stats = self.stats.write();
        stats.total_inferences += 1;
        stats.total_latency_us += elapsed.as_micros() as u64;
        
        result
    }

    /// Single flow inference
    pub fn infer_flow(&self, flow: &FlowFeatures) -> NetworkPrediction {
        self.network.predict(flow)
    }

    /// UBA inference
    pub fn infer_session(&self, session: &UserSession) -> UbaPrediction {
        self.uba.predict(session)
    }

    /// Malware inference
    pub fn infer_tls(&self, fingerprint: &TlsFingerprint, flow: &FlowFeatures) -> MalwarePrediction {
        self.malware.predict(fingerprint, flow)
    }

    /// Get inference stats
    pub fn stats(&self) -> InferenceStats {
        self.stats.read().clone()
    }

    /// Reload models (hot reload)
    pub fn reload_models(&self, path: &str) -> Result<(), OstieError> {
        tracing::info!("Hot-reloading models from {}", path);
        self.dns.load(&format!("{}/dns", path))?;
        self.network.load(&format!("{}/network", path))?;
        self.uba.load(&format!("{}/uba", path))?;
        self.malware.load(&format!("{}/malware", path))?;
        tracing::info!("Models reloaded successfully");
        Ok(())
    }
}

impl Default for InferenceEngine {
    fn default() -> Self { Self::new() }
}

/// Inference statistics
#[derive(Debug, Clone, Default)]
pub struct InferenceStats {
    pub total_inferences: u64,
    pub total_latency_us: u64,
    pub dns_inferences: u64,
    pub network_inferences: u64,
    pub uba_inferences: u64,
}

impl InferenceStats {
    /// Average latency in microseconds
    pub fn avg_latency_us(&self) -> f64 {
        if self.total_inferences == 0 { 0.0 }
        else { self.total_latency_us as f64 / self.total_inferences as f64 }
    }

    /// Throughput (inferences per second)
    pub fn throughput(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs == 0.0 { 0.0 }
        else { self.total_inferences as f64 / elapsed_secs }
    }
}
