//! Threat Intelligence API
//!
//! REST and gRPC API for threat intelligence operations.

use crate::{Indicator, IocType, Confidence, Severity, ThreatIntelService, ThreatIntelSnapshot};
use crate::matching::{IocMatchingEngine, IocMatch, IocCheckRequest};
use crate::hunting::{ThreatHuntingEngine, HuntingQuery, HuntingResult};
use crate::sinkhole::{DnsSinkhole, SinkholeSnapshot};
use std::sync::Arc;

/// Threat Intelligence API Service
pub struct ThreatIntelApi {
    service: Arc<ThreatIntelService>,
    matching_engine: Arc<IocMatchingEngine>,
    hunting_engine: Arc<ThreatHuntingEngine>,
    sinkhole: Arc<DnsSinkhole>,
}

impl ThreatIntelApi {
    pub fn new(
        service: Arc<ThreatIntelService>,
        matching_engine: Arc<IocMatchingEngine>,
        sinkhole: Arc<DnsSinkhole>,
    ) -> Self {
        let hunting_engine = Arc::new(ThreatHuntingEngine::new(service.clone()));
        
        Self {
            service,
            matching_engine,
            hunting_engine,
            sinkhole,
        }
    }
    
    // =========================================================================
    // IOC Lookup APIs
    // =========================================================================
    
    /// Lookup a single IOC
    pub fn lookup(&self, request: LookupRequest) -> LookupResponse {
        let result = match request.ioc_type {
            IocType::IPv4 | IocType::IPv6 => {
                if let Ok(ip) = request.value.parse() {
                    self.matching_engine.check_ip(ip)
                } else {
                    None
                }
            }
            IocType::Domain => {
                self.matching_engine.check_domain(&request.value)
            }
            IocType::Url => {
                self.matching_engine.check_url(&request.value)
            }
            IocType::FileHashMd5 | IocType::FileHashSha1 | IocType::FileHashSha256 => {
                self.matching_engine.check_hash(&request.value)
            }
            _ => None,
        };
        
        LookupResponse {
            found: result.is_some(),
            ioc_match: result,
            lookup_time_us: 0, // Would be measured
        }
    }
    
    /// Batch lookup multiple IOCs
    pub fn batch_lookup(&self, requests: Vec<LookupRequest>) -> Vec<LookupResponse> {
        requests.iter().map(|req| self.lookup(req.clone())).collect()
    }
    
    // =========================================================================
    // Feed Management APIs
    // =========================================================================
    
    /// Get all configured feeds
    pub fn list_feeds(&self) -> Vec<FeedInfo> {
        self.service.feeds.get_all_status().into_iter()
            .map(|s| FeedInfo {
                feed_id: s.feed_id,
                last_poll: s.last_poll,
                next_poll: s.next_poll,
                indicators_total: s.indicators_total,
                health: format!("{:?}", s.health),
            })
            .collect()
    }
    
    /// Trigger manual feed poll
    pub async fn poll_feed(&self, feed_id: &str) -> Result<PollResult, ApiError> {
        let indicators = self.service.feeds.poll_feed(feed_id).await
            .map_err(|e| ApiError::FeedError(e.to_string()))?;
        
        // Ingest indicators
        for indicator in &indicators {
            self.service.ingest(indicator.clone());
            self.matching_engine.add(indicator);
            self.sinkhole.add_indicator(indicator);
        }
        
        Ok(PollResult {
            feed_id: feed_id.to_string(),
            indicators_fetched: indicators.len(),
        })
    }
    
    // =========================================================================
    // Hunting APIs
    // =========================================================================
    
    /// Execute a hunting query
    pub async fn hunt(&self, query: HuntingQuery) -> HuntingResult {
        self.hunting_engine.hunt(&query).await
    }
    
    /// Get built-in hunting queries
    pub fn list_hunting_queries(&self) -> Vec<HuntingQueryInfo> {
        self.hunting_engine.get_builtin_queries()
            .iter()
            .map(|q| HuntingQueryInfo {
                id: q.id.clone(),
                name: q.name.clone(),
                description: q.description.clone(),
                mitre_technique: q.mitre_technique.clone(),
                severity: format!("{:?}", q.severity),
            })
            .collect()
    }
    
    // =========================================================================
    // Sinkhole APIs
    // =========================================================================
    
    /// Check if domain is blocked
    pub fn check_sinkhole(&self, domain: &str) -> SinkholeCheckResult {
        let entry = self.sinkhole.should_block(domain);
        
        SinkholeCheckResult {
            domain: domain.to_string(),
            blocked: entry.is_some(),
            reason: entry.as_ref().map(|e| e.reason.clone()),
            category: entry.map(|e| format!("{:?}", e.category)),
        }
    }
    
    /// Add domain to sinkhole
    pub fn add_to_sinkhole(&self, request: SinkholeAddRequest) {
        self.sinkhole.block(
            &request.domain,
            &request.reason,
            crate::sinkhole::SinkholeCategory::Custom,
        );
    }
    
    /// Get sinkhole statistics
    pub fn sinkhole_stats(&self) -> SinkholeSnapshot {
        self.sinkhole.get_stats()
    }
    
    /// Export sinkhole in various formats
    pub fn export_sinkhole(&self, format: ExportFormat) -> String {
        match format {
            ExportFormat::Rpz => self.sinkhole.to_rpz(),
            ExportFormat::Pihole => self.sinkhole.to_pihole(),
            ExportFormat::Hosts => self.sinkhole.to_hosts(),
        }
    }
    
    // =========================================================================
    // Statistics APIs
    // =========================================================================
    
    /// Get overall statistics
    pub fn get_stats(&self) -> ApiStats {
        let intel_stats = self.service.get_stats();
        let matching_stats = self.matching_engine.get_stats();
        let sinkhole_stats = self.sinkhole.get_stats();
        
        ApiStats {
            indicators_total: intel_stats.indicators_total,
            feeds_active: intel_stats.feeds_active,
            lookups_total: matching_stats.lookups_total,
            lookups_hit: matching_stats.lookups_hit,
            sinkhole_domains: sinkhole_stats.domains_blocked,
            sinkhole_queries_blocked: sinkhole_stats.queries_blocked,
        }
    }
}

// =============================================================================
// Request/Response Types
// =============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LookupRequest {
    pub ioc_type: IocType,
    pub value: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LookupResponse {
    pub found: bool,
    pub ioc_match: Option<IocMatch>,
    pub lookup_time_us: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeedInfo {
    pub feed_id: String,
    pub last_poll: Option<chrono::DateTime<chrono::Utc>>,
    pub next_poll: Option<chrono::DateTime<chrono::Utc>>,
    pub indicators_total: u64,
    pub health: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PollResult {
    pub feed_id: String,
    pub indicators_fetched: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HuntingQueryInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub mitre_technique: Option<String>,
    pub severity: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SinkholeCheckResult {
    pub domain: String,
    pub blocked: bool,
    pub reason: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SinkholeAddRequest {
    pub domain: String,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExportFormat {
    Rpz,
    Pihole,
    Hosts,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiStats {
    pub indicators_total: u64,
    pub feeds_active: u32,
    pub lookups_total: u64,
    pub lookups_hit: u64,
    pub sinkhole_domains: u64,
    pub sinkhole_queries_blocked: u64,
}

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    FeedError(String),
    InvalidRequest(String),
    InternalError(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "Not found: {}", msg),
            Self::FeedError(msg) => write!(f, "Feed error: {}", msg),
            Self::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

// =============================================================================
// HTTP Routes (Axum-style handlers)
// =============================================================================

pub mod routes {
    use super::*;
    
    /// GET /api/v1/ioc/lookup?type=ipv4&value=1.2.3.4
    pub async fn lookup_ioc(
        api: Arc<ThreatIntelApi>,
        ioc_type: IocType,
        value: String,
    ) -> LookupResponse {
        api.lookup(LookupRequest { ioc_type, value })
    }
    
    /// POST /api/v1/ioc/batch-lookup
    pub async fn batch_lookup_ioc(
        api: Arc<ThreatIntelApi>,
        requests: Vec<LookupRequest>,
    ) -> Vec<LookupResponse> {
        api.batch_lookup(requests)
    }
    
    /// GET /api/v1/feeds
    pub async fn list_feeds(api: Arc<ThreatIntelApi>) -> Vec<FeedInfo> {
        api.list_feeds()
    }
    
    /// POST /api/v1/feeds/{feed_id}/poll
    pub async fn poll_feed(
        api: Arc<ThreatIntelApi>,
        feed_id: String,
    ) -> Result<PollResult, ApiError> {
        api.poll_feed(&feed_id).await
    }
    
    /// GET /api/v1/hunting/queries
    pub async fn list_hunting_queries(
        api: Arc<ThreatIntelApi>,
    ) -> Vec<HuntingQueryInfo> {
        api.list_hunting_queries()
    }
    
    /// POST /api/v1/hunting/run
    pub async fn run_hunting_query(
        api: Arc<ThreatIntelApi>,
        query: HuntingQuery,
    ) -> HuntingResult {
        api.hunt(query).await
    }
    
    /// GET /api/v1/sinkhole/check?domain=example.com
    pub async fn check_sinkhole(
        api: Arc<ThreatIntelApi>,
        domain: String,
    ) -> SinkholeCheckResult {
        api.check_sinkhole(&domain)
    }
    
    /// POST /api/v1/sinkhole/add
    pub async fn add_to_sinkhole(
        api: Arc<ThreatIntelApi>,
        request: SinkholeAddRequest,
    ) {
        api.add_to_sinkhole(request)
    }
    
    /// GET /api/v1/sinkhole/export?format=rpz
    pub async fn export_sinkhole(
        api: Arc<ThreatIntelApi>,
        format: ExportFormat,
    ) -> String {
        api.export_sinkhole(format)
    }
    
    /// GET /api/v1/stats
    pub async fn get_stats(api: Arc<ThreatIntelApi>) -> ApiStats {
        api.get_stats()
    }
}
