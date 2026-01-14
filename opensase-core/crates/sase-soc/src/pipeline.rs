//! Event Processing Pipeline
//!
//! Unified pipeline: Ingest → Normalize → Enrich → Correlate → Route

use crate::{SecurityEvent, SecurityAlert};
use crate::normalize::EventNormalizer;
use crate::enrichment::EventEnricher;
use crate::correlation::EventCorrelator;
use crate::siem::SiemIntegration;
use crate::soar::SoarEngine;
use crate::alerts::AlertRouter;

pub struct EventPipeline {
    normalizer: EventNormalizer,
    enricher: EventEnricher,
    correlator: EventCorrelator,
    siem: SiemIntegration,
    soar: SoarEngine,
    router: AlertRouter,
    config: PipelineConfig,
    stats: PipelineStats,
}

#[derive(Clone)]
pub struct PipelineConfig {
    pub siem_forwarding: bool,
    pub auto_enrichment: bool,
    pub correlation_enabled: bool,
    pub soar_enabled: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            siem_forwarding: true,
            auto_enrichment: true,
            correlation_enabled: true,
            soar_enabled: true,
        }
    }
}

struct PipelineStats {
    events_received: std::sync::atomic::AtomicU64,
    events_processed: std::sync::atomic::AtomicU64,
    alerts_generated: std::sync::atomic::AtomicU64,
    processing_errors: std::sync::atomic::AtomicU64,
}

impl EventPipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            normalizer: EventNormalizer::new(),
            enricher: EventEnricher::new(),
            correlator: EventCorrelator::new(),
            siem: SiemIntegration::new(),
            soar: SoarEngine::new(),
            router: AlertRouter::new(),
            config,
            stats: PipelineStats {
                events_received: std::sync::atomic::AtomicU64::new(0),
                events_processed: std::sync::atomic::AtomicU64::new(0),
                alerts_generated: std::sync::atomic::AtomicU64::new(0),
                processing_errors: std::sync::atomic::AtomicU64::new(0),
            },
        }
    }
    
    /// Process raw log through full pipeline
    pub async fn process_raw(&self, source_type: &str, raw: &str) -> Result<PipelineResult, PipelineError> {
        self.stats.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        // Stage 1: Normalize
        let mut event = self.normalizer.normalize(source_type, raw)
            .map_err(|e| {
                self.stats.processing_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                PipelineError::NormalizationFailed(e.to_string())
            })?;
        
        // Stage 2: Enrich
        let enrichment = if self.config.auto_enrichment {
            self.enricher.enrich(&mut event).await
        } else {
            crate::enrichment::EnrichmentResult::default()
        };
        
        // Stage 3: Forward to SIEM
        if self.config.siem_forwarding {
            self.siem.forward(&event).await;
        }
        
        // Stage 4: Correlate
        let alert = if self.config.correlation_enabled {
            self.correlator.process(&event).await
        } else {
            None
        };
        
        // Stage 5: Route alert and trigger SOAR
        if let Some(ref alert) = alert {
            self.stats.alerts_generated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.router.route(alert).await;
            
            if self.config.soar_enabled {
                self.soar.trigger(alert).await;
            }
        }
        
        self.stats.events_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        Ok(PipelineResult {
            event,
            enrichment,
            alert,
        })
    }
    
    /// Process pre-normalized event
    pub async fn process_event(&self, mut event: SecurityEvent) -> Result<PipelineResult, PipelineError> {
        self.stats.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        // Enrich
        let enrichment = if self.config.auto_enrichment {
            self.enricher.enrich(&mut event).await
        } else {
            crate::enrichment::EnrichmentResult::default()
        };
        
        // Forward
        if self.config.siem_forwarding {
            self.siem.forward(&event).await;
        }
        
        // Correlate
        let alert = if self.config.correlation_enabled {
            self.correlator.process(&event).await
        } else {
            None
        };
        
        // Route
        if let Some(ref alert) = alert {
            self.stats.alerts_generated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.router.route(alert).await;
            
            if self.config.soar_enabled {
                self.soar.trigger(alert).await;
            }
        }
        
        self.stats.events_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        Ok(PipelineResult {
            event,
            enrichment,
            alert,
        })
    }
    
    /// Batch process events
    pub async fn process_batch(&self, events: Vec<SecurityEvent>) -> Vec<PipelineResult> {
        let mut results = Vec::with_capacity(events.len());
        for event in events {
            if let Ok(result) = self.process_event(event).await {
                results.push(result);
            }
        }
        results
    }
    
    /// Get pipeline stats
    pub fn stats(&self) -> PipelineMetrics {
        PipelineMetrics {
            events_received: self.stats.events_received.load(std::sync::atomic::Ordering::Relaxed),
            events_processed: self.stats.events_processed.load(std::sync::atomic::Ordering::Relaxed),
            alerts_generated: self.stats.alerts_generated.load(std::sync::atomic::Ordering::Relaxed),
            processing_errors: self.stats.processing_errors.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
    
    /// Access components
    pub fn siem(&self) -> &SiemIntegration { &self.siem }
    pub fn soar(&self) -> &SoarEngine { &self.soar }
    pub fn correlator(&self) -> &EventCorrelator { &self.correlator }
}

#[derive(Clone)]
pub struct PipelineResult {
    pub event: SecurityEvent,
    pub enrichment: crate::enrichment::EnrichmentResult,
    pub alert: Option<SecurityAlert>,
}

#[derive(Clone, serde::Serialize)]
pub struct PipelineMetrics {
    pub events_received: u64,
    pub events_processed: u64,
    pub alerts_generated: u64,
    pub processing_errors: u64,
}

#[derive(Debug)]
pub enum PipelineError {
    NormalizationFailed(String),
    EnrichmentFailed(String),
    CorrelationFailed(String),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NormalizationFailed(e) => write!(f, "Normalization: {}", e),
            Self::EnrichmentFailed(e) => write!(f, "Enrichment: {}", e),
            Self::CorrelationFailed(e) => write!(f, "Correlation: {}", e),
        }
    }
}

impl std::error::Error for PipelineError {}
