//! OpenSASE Security Operations Platform (OSOP)
//!
//! Comprehensive SOC and SOAR integration:
//! - SIEM integration (Splunk, Elastic, Sentinel, QRadar)
//! - SOAR playbook automation
//! - Case management
//! - Threat hunting
//! - Forensic collection
//! - Compliance reporting
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    SECURITY OPERATIONS PLATFORM                          │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │    SIEM      │  │    SOAR      │  │    Case      │  │   Threat    │ │
//! │  │ Integration  │  │  Playbooks   │  │ Management   │  │   Hunting   │ │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
//! │         │                 │                 │                 │         │
//! │         └─────────────────┼─────────────────┼─────────────────┘         │
//! │                           │                 │                           │
//! │                           ▼                 ▼                           │
//! │                    ┌──────────────────────────────┐                    │
//! │                    │     Unified Event Bus        │                    │
//! │                    └──────────────────────────────┘                    │
//! │                                                                          │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
//! │  │  Forensics   │  │  Compliance  │  │   Alert      │  │   Metrics   │ │
//! │  │  Collection  │  │  Reporting   │  │   Router     │  │   Export    │ │
//! │  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

// Module declarations
pub mod siem;
pub mod soar;
pub mod cases;
pub mod hunting;
pub mod forensics;
pub mod compliance;
pub mod alerts;
pub mod normalize;
pub mod enrichment;
pub mod correlation;
pub mod pipeline;

// =============================================================================
// Core Types
// =============================================================================

/// Security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub event_type: EventType,
    pub severity: Severity,
    pub source: EventSource,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub raw_data: serde_json::Value,
    pub indicators: Vec<Indicator>,
    pub tags: Vec<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    // Network events
    NetworkIntrusion,
    DdosAttack,
    PortScan,
    SuspiciousTraffic,
    
    // Endpoint events
    MalwareDetected,
    SuspiciousProcess,
    FileIntegrity,
    PrivilegeEscalation,
    
    // Identity events
    AuthenticationFailure,
    BruteForceAttempt,
    ImpossibleTravel,
    AccountCompromise,
    
    // Data events
    DataExfiltration,
    DlpViolation,
    UnauthorizedAccess,
    
    // Application events
    WebAttack,
    ApiAbuse,
    BotActivity,
    
    // Policy events
    PolicyViolation,
    ComplianceViolation,
    
    // Custom
    Custom,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSource {
    pub system: String,
    pub component: String,
    pub host: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
    Hash,
    Email,
    Username,
    FileName,
    Process,
    Registry,
    Certificate,
}

/// Security alert (enriched event)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub events: Vec<String>,
    pub alert_type: String,
    pub severity: Severity,
    pub status: AlertStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub assigned_to: Option<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub enrichment: AlertEnrichment,
    pub case_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    New,
    Triaging,
    InProgress,
    Resolved,
    FalsePositive,
    Escalated,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertEnrichment {
    pub threat_intel: Vec<ThreatIntelMatch>,
    pub asset_info: Option<AssetInfo>,
    pub user_info: Option<UserInfo>,
    pub related_alerts: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelMatch {
    pub feed: String,
    pub indicator: String,
    pub threat_type: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInfo {
    pub asset_id: String,
    pub asset_type: String,
    pub hostname: Option<String>,
    pub owner: Option<String>,
    pub criticality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub department: Option<String>,
    pub risk_level: String,
}

// =============================================================================
// Security Operations Platform
// =============================================================================

/// Main SOC platform
pub struct SecurityOperationsPlatform {
    /// SIEM integrations
    pub siem: siem::SiemIntegration,
    /// SOAR engine
    pub soar: soar::SoarEngine,
    /// Case management
    pub cases: cases::CaseManager,
    /// Threat hunting
    pub hunting: hunting::ThreatHunter,
    /// Forensics
    pub forensics: forensics::ForensicsCollector,
    /// Compliance
    pub compliance: compliance::ComplianceEngine,
    /// Alert router
    pub alerts: alerts::AlertRouter,
    /// Event bus
    event_bus: EventBus,
    /// Config
    config: SopConfig,
}

#[derive(Clone)]
pub struct SopConfig {
    pub tenant_id: String,
    pub siem_enabled: bool,
    pub soar_enabled: bool,
    pub auto_enrichment: bool,
    pub default_severity_threshold: Severity,
}

impl Default for SopConfig {
    fn default() -> Self {
        Self {
            tenant_id: "default".to_string(),
            siem_enabled: true,
            soar_enabled: true,
            auto_enrichment: true,
            default_severity_threshold: Severity::Low,
        }
    }
}

struct EventBus {
    subscribers: dashmap::DashMap<String, Vec<EventSubscriber>>,
}

type EventSubscriber = Arc<dyn Fn(&SecurityEvent) + Send + Sync>;

impl SecurityOperationsPlatform {
    pub fn new(config: SopConfig) -> Self {
        Self {
            siem: siem::SiemIntegration::new(),
            soar: soar::SoarEngine::new(),
            cases: cases::CaseManager::new(),
            hunting: hunting::ThreatHunter::new(),
            forensics: forensics::ForensicsCollector::new(),
            compliance: compliance::ComplianceEngine::new(),
            alerts: alerts::AlertRouter::new(),
            event_bus: EventBus {
                subscribers: dashmap::DashMap::new(),
            },
            config,
        }
    }
    
    /// Ingest security event
    pub async fn ingest_event(&self, event: SecurityEvent) {
        tracing::debug!("Ingesting event: {} - {:?}", event.id, event.event_type);
        
        // Forward to SIEM
        if self.config.siem_enabled {
            self.siem.forward(&event).await;
        }
        
        // Check if alert should be generated
        if event.severity >= self.config.default_severity_threshold {
            let alert = self.create_alert(&event).await;
            
            // Route alert
            self.alerts.route(&alert).await;
            
            // Trigger SOAR playbooks
            if self.config.soar_enabled {
                self.soar.trigger(&alert).await;
            }
        }
        
        // Notify subscribers
        self.notify_subscribers(&event);
    }
    
    async fn create_alert(&self, event: &SecurityEvent) -> SecurityAlert {
        let mut alert = SecurityAlert {
            id: Uuid::new_v4().to_string(),
            events: vec![event.id.clone()],
            alert_type: format!("{:?}", event.event_type),
            severity: event.severity,
            status: AlertStatus::New,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            assigned_to: None,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            enrichment: AlertEnrichment::default(),
            case_id: None,
        };
        
        // Auto-enrich
        if self.config.auto_enrichment {
            alert.enrichment = self.enrich_alert(event).await;
        }
        
        // Map to MITRE ATT&CK
        let (tactics, techniques) = self.map_to_mitre(&event.event_type);
        alert.mitre_tactics = tactics;
        alert.mitre_techniques = techniques;
        
        alert
    }
    
    async fn enrich_alert(&self, event: &SecurityEvent) -> AlertEnrichment {
        let mut enrichment = AlertEnrichment::default();
        
        // Check indicators against threat intel
        for indicator in &event.indicators {
            if let Some(match_result) = self.hunting.check_indicator(indicator).await {
                enrichment.threat_intel.push(match_result);
            }
        }
        
        // Calculate risk score
        enrichment.risk_score = self.calculate_risk_score(event, &enrichment);
        
        enrichment
    }
    
    fn calculate_risk_score(&self, event: &SecurityEvent, enrichment: &AlertEnrichment) -> f64 {
        let mut score = match event.severity {
            Severity::Info => 10.0,
            Severity::Low => 25.0,
            Severity::Medium => 50.0,
            Severity::High => 75.0,
            Severity::Critical => 95.0,
        };
        
        // Threat intel matches increase score
        score += enrichment.threat_intel.len() as f64 * 10.0;
        
        // Asset criticality
        if let Some(asset) = &enrichment.asset_info {
            if asset.criticality == "critical" {
                score += 20.0;
            }
        }
        
        score.min(100.0)
    }
    
    fn map_to_mitre(&self, event_type: &EventType) -> (Vec<String>, Vec<String>) {
        match event_type {
            EventType::NetworkIntrusion => (
                vec!["TA0001".to_string()], // Initial Access
                vec!["T1190".to_string()], // Exploit Public-Facing Application
            ),
            EventType::BruteForceAttempt => (
                vec!["TA0006".to_string()], // Credential Access
                vec!["T1110".to_string()], // Brute Force
            ),
            EventType::PrivilegeEscalation => (
                vec!["TA0004".to_string()], // Privilege Escalation
                vec!["T1068".to_string()], // Exploitation for Privilege Escalation
            ),
            EventType::DataExfiltration => (
                vec!["TA0010".to_string()], // Exfiltration
                vec!["T1041".to_string()], // Exfiltration Over C2 Channel
            ),
            EventType::MalwareDetected => (
                vec!["TA0002".to_string()], // Execution
                vec!["T1204".to_string()], // User Execution
            ),
            _ => (vec![], vec![]),
        }
    }
    
    fn notify_subscribers(&self, event: &SecurityEvent) {
        let event_type = format!("{:?}", event.event_type);
        if let Some(subs) = self.event_bus.subscribers.get(&event_type) {
            for sub in subs.iter() {
                sub(event);
            }
        }
    }
    
    /// Subscribe to events
    pub fn subscribe(&self, event_type: &str, handler: EventSubscriber) {
        self.event_bus.subscribers
            .entry(event_type.to_string())
            .or_insert_with(Vec::new)
            .push(handler);
    }
    
    /// Get platform stats
    pub async fn get_stats(&self) -> PlatformStats {
        PlatformStats {
            events_today: self.siem.get_event_count().await,
            alerts_open: self.alerts.get_open_count().await,
            cases_active: self.cases.get_active_count().await,
            playbooks_triggered: self.soar.get_execution_count().await,
            mean_time_to_respond: self.cases.get_mttr().await,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformStats {
    pub events_today: u64,
    pub alerts_open: u64,
    pub cases_active: u64,
    pub playbooks_triggered: u64,
    pub mean_time_to_respond: f64,
}
