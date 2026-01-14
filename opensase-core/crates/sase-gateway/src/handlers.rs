//! API Handlers

use axum::{
    Extension,
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::AppState;
use sase_common::{PolicyKey, AppClass};
use sase_path::WanLink;
use sase_ml::anomaly::SessionFeatures;

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Health check
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Readiness check
pub async fn ready(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    // Check all components
    let policy_ready = state.policy.store().version() >= 0;
    let dlp_ready = state.dlp.classifier_count() > 0;

    if policy_ready && dlp_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Metrics endpoint
pub async fn metrics(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.policy.stats();
    
    let metrics = format!(
        r#"# HELP opensase_policy_lookups_total Total policy lookups
# TYPE opensase_policy_lookups_total counter
opensase_policy_lookups_total {}

# HELP opensase_policy_cache_hits_total Cache hits
# TYPE opensase_policy_cache_hits_total counter
opensase_policy_cache_hits_total {}

# HELP opensase_policy_cache_hit_rate Cache hit rate
# TYPE opensase_policy_cache_hit_rate gauge
opensase_policy_cache_hit_rate {}
"#,
        stats.total_lookups,
        stats.cache_hits,
        stats.cache_hit_rate,
    );

    (StatusCode::OK, metrics)
}

// === Policy Handlers ===

#[derive(Deserialize)]
pub struct PolicyLookupRequest {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Serialize)]
pub struct PolicyLookupResponse {
    pub action: String,
    pub rule_id: u32,
    pub lookup_ns: u64,
}

pub async fn policy_lookup(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<PolicyLookupRequest>,
) -> Json<PolicyLookupResponse> {
    let key = PolicyKey::from_ipv4(
        parse_ip(&req.src_ip),
        parse_ip(&req.dst_ip),
        req.src_port,
        req.dst_port,
        req.protocol,
    );

    let (decision, elapsed_us) = state.policy.lookup_timed(&key);

    Json(PolicyLookupResponse {
        action: format!("{:?}", decision.action),
        rule_id: decision.rule_id,
        lookup_ns: elapsed_us * 1000,
    })
}

pub async fn policy_stats(
    Extension(state): Extension<Arc<AppState>>,
) -> Json<sase_policy::EngineStats> {
    Json(state.policy.stats())
}

// === DLP Handlers ===

#[derive(Deserialize)]
pub struct DLPScanRequest {
    pub content: String,
}

#[derive(Serialize)]
pub struct DLPScanResponse {
    pub has_matches: bool,
    pub match_count: usize,
    pub highest_severity: Option<String>,
    pub scan_time_us: u64,
    pub throughput_mbps: f64,
}

pub async fn dlp_scan(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<DLPScanRequest>,
) -> Json<DLPScanResponse> {
    let result = state.dlp.scan(&req.content);

    Json(DLPScanResponse {
        has_matches: result.has_matches(),
        match_count: result.match_count(),
        highest_severity: result.highest_severity.map(|s| format!("{:?}", s)),
        scan_time_us: result.scan_time_us,
        throughput_mbps: result.throughput_mbps,
    })
}

#[derive(Serialize)]
pub struct ClassifierInfo {
    pub name: String,
    pub severity: String,
}

pub async fn dlp_classifiers() -> Json<Vec<ClassifierInfo>> {
    let classifiers: Vec<_> = sase_dlp::default_classifiers()
        .iter()
        .map(|c| ClassifierInfo {
            name: c.name.clone(),
            severity: format!("{:?}", c.severity),
        })
        .collect();

    Json(classifiers)
}

// === Path Handlers ===

#[derive(Deserialize)]
pub struct PathRecommendRequest {
    pub site: String,
    pub app_class: String,
}

#[derive(Serialize)]
pub struct PathRecommendResponse {
    pub primary: String,
    pub backup: Option<String>,
    pub score: f32,
    pub confidence: f32,
    pub reason: String,
}

pub async fn path_recommend(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<PathRecommendRequest>,
) -> Json<PathRecommendResponse> {
    let app_class = match req.app_class.to_lowercase().as_str() {
        "voice" => AppClass::Voice,
        "video" => AppClass::Video,
        "web" => AppClass::Web,
        "bulk" => AppClass::Bulk,
        _ => AppClass::Unknown,
    };

    let rec = state.path_selector.recommend(&req.site, app_class);

    Json(PathRecommendResponse {
        primary: format!("{:?}", rec.primary),
        backup: rec.backup.map(|b| format!("{:?}", b)),
        score: rec.primary_score,
        confidence: rec.confidence,
        reason: rec.reason,
    })
}

#[derive(Deserialize)]
pub struct RecordProbeRequest {
    pub site: String,
    pub wan: String,
    pub latency_us: u32,
    pub jitter_us: u32,
    pub loss_permille: u16,
    pub bandwidth_kbps: u32,
}

pub async fn path_record_probe(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<RecordProbeRequest>,
) -> StatusCode {
    let wan = match req.wan.to_lowercase().as_str() {
        "wan1" => WanLink::Wan1,
        "wan2" => WanLink::Wan2,
        "wan3" => WanLink::Wan3,
        "lte" => WanLink::Lte,
        _ => return StatusCode::BAD_REQUEST,
    };

    state.path_selector.record_probe(
        &req.site,
        wan,
        sase_path::ProbeResult::success(
            req.latency_us,
            req.jitter_us,
            req.loss_permille,
            req.bandwidth_kbps,
        ),
    );

    StatusCode::OK
}

// === ML Handlers ===

#[derive(Deserialize)]
pub struct MLPredictRequest {
    pub site: String,
}

#[derive(Serialize)]
pub struct MLPredictResponse {
    pub predicted_path: String,
    pub confidence: f32,
    pub congestion_warnings: Vec<String>,
}

pub async fn ml_predict(
    Extension(state): Extension<Arc<AppState>>,
    Json(_req): Json<MLPredictRequest>,
) -> Json<MLPredictResponse> {
    let (path, confidence) = state.predictor.predict();
    let congestion = state.predictor.predict_congestion();

    let warnings: Vec<_> = congestion.iter()
        .map(|(wan, time_us)| format!("{:?} may congest in {}μs", wan, time_us))
        .collect();

    Json(MLPredictResponse {
        predicted_path: format!("{:?}", path),
        confidence,
        congestion_warnings: warnings,
    })
}

#[derive(Deserialize)]
pub struct RiskScoreRequest {
    pub user_id: String,
    pub source_ip: String,
    pub request_count: u32,
    pub unique_destinations: u32,
    pub data_volume: u64,
    pub hour_of_day: u8,
    pub new_location: bool,
    pub device_trust: f32,
    pub mfa_used: bool,
}

#[derive(Serialize)]
pub struct RiskScoreResponse {
    pub risk: f32,
    pub anomaly_score: f32,
    pub require_stepup: bool,
    pub block: bool,
}

pub async fn ml_risk_score(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<RiskScoreRequest>,
) -> Json<RiskScoreResponse> {
    let features = SessionFeatures {
        user_id: req.user_id,
        source_ip: req.source_ip,
        request_count: req.request_count,
        unique_destinations: req.unique_destinations,
        data_volume: req.data_volume,
        hour_of_day: req.hour_of_day,
        day_of_week: 2,  // Placeholder
        new_location: req.new_location,
        device_trust: req.device_trust,
        mfa_used: req.mfa_used,
    };

    let score = state.anomaly.analyze(&features);

    Json(RiskScoreResponse {
        risk: score.risk,
        anomaly_score: score.anomaly_score,
        require_stepup: score.require_stepup,
        block: score.block,
    })
}

// Helper function
fn parse_ip(s: &str) -> u32 {
    let parts: Vec<u8> = s.split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    
    if parts.len() == 4 {
        u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]])
    } else {
        0
    }
}
