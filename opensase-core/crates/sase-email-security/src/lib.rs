//! OpenSASE Email Security Gateway (OESG)
//!
//! Comprehensive email security with anti-spam, anti-phishing, anti-malware,
//! BEC detection, and DLP integration.
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    EMAIL SECURITY GATEWAY                            │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Inbound Email (SMTP)                                                │
//! │        │                                                            │
//! │        ▼                                                            │
//! │ ┌────────────────┐                                                  │
//! │ │ Connection     │ IP reputation, rate limit, greylisting           │
//! │ │ Filtering      │                                                  │
//! │ └───────┬────────┘                                                  │
//! │         ▼                                                            │
//! │ ┌────────────────┐                                                  │
//! │ │ Authentication │ DMARC, DKIM, SPF validation                      │
//! │ │ Validation     │                                                  │
//! │ └───────┬────────┘                                                  │
//! │         ▼                                                            │
//! │ ┌────────────────┐                                                  │
//! │ │ Content        │ Spam classifier, phishing detection              │
//! │ │ Analysis       │ URL rewriting, brand spoofing check              │
//! │ └───────┬────────┘                                                  │
//! │         ▼                                                            │
//! │ ┌────────────────┐                                                  │
//! │ │ Attachment     │ Type detection, macro analysis                   │
//! │ │ Scanning       │ Malware sandbox, CDR sanitization                │
//! │ └───────┬────────┘                                                  │
//! │         ▼                                                            │
//! │ ┌────────────────┐                                                  │
//! │ │ BEC Detection  │ NLP analysis, impersonation detection            │
//! │ │ (ML/NLP)       │ Executive fraud protection                       │
//! │ └───────┬────────┘                                                  │
//! │         ▼                                                            │
//! │ ┌────────────────┐                                                  │
//! │ │ DLP Scanning   │ Sensitive data detection (outbound)              │
//! │ │                │                                                  │
//! │ └───────┬────────┘                                                  │
//! │         ▼                                                            │
//! │    DELIVER / QUARANTINE / REJECT                                    │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Targets
//! - 99.9% spam/phishing block rate
//! - <0.001% false positive rate
//! - <5 second average processing time
//! - Zero-day malware detection via sandboxing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub mod parser;
pub mod mta;
pub mod spam;
pub mod phishing;
pub mod reputation;
pub mod attachments;
pub mod sandbox;
pub mod bec;
pub mod dmarc;
pub mod dlp;
pub mod urlrewrite;
pub mod outbound;
pub mod quarantine;
pub mod smtp;
pub mod auth;
pub mod blocklists;
pub mod sandbox_advanced;
pub mod pipeline;

// =============================================================================
// Core Types
// =============================================================================

/// Unique email message identifier
pub type MessageId = String;

/// Email message for security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    pub id: MessageId,
    pub envelope: EmailEnvelope,
    pub headers: EmailHeaders,
    pub body: EmailBody,
    pub attachments: Vec<Attachment>,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub size_bytes: usize,
}

/// SMTP envelope information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailEnvelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub client_ip: IpAddr,
    pub client_hostname: Option<String>,
    pub helo: String,
    pub authenticated_user: Option<String>,
    pub tls_version: Option<String>,
}

/// Parsed email headers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmailHeaders {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub reply_to: Option<String>,
    pub return_path: Option<String>,
    pub received: Vec<String>,
    pub dkim_signature: Option<String>,
    pub authentication_results: Option<String>,
    pub x_headers: HashMap<String, String>,
}

/// Email body content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailBody {
    pub content_type: ContentType,
    pub text_plain: Option<String>,
    pub text_html: Option<String>,
    pub urls: Vec<ExtractedUrl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    TextPlain,
    TextHtml,
    Multipart,
    Unknown,
}

/// URL extracted from email body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedUrl {
    pub url: String,
    pub display_text: Option<String>,
    pub context: UrlContext,
    pub is_shortened: bool,
    pub final_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UrlContext {
    Body,
    Attachment,
    Header,
}

/// Email attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: usize,
    pub hash_sha256: String,
    pub is_executable: bool,
    pub is_archive: bool,
    pub nested_files: Vec<NestedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedFile {
    pub path: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: usize,
    pub hash_sha256: String,
}

// =============================================================================
// Verdict Types
// =============================================================================

/// Final verdict for an email
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerdict {
    pub message_id: MessageId,
    pub action: VerdictAction,
    pub overall_score: f64,
    pub spam_score: f64,
    pub phishing_score: f64,
    pub malware_score: f64,
    pub bec_score: f64,
    pub dlp_violations: Vec<DlpViolation>,
    pub categories: Vec<ThreatCategory>,
    pub reasons: Vec<VerdictReason>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictAction {
    /// Allow delivery
    Deliver,
    /// Deliver with modifications (URL rewriting, etc)
    DeliverModified,
    /// Move to quarantine
    Quarantine,
    /// Reject at SMTP level
    Reject,
    /// Silently drop
    Drop,
    /// Defer for sandbox analysis
    Defer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    Spam,
    Phishing,
    Malware,
    Bec,
    Ransomware,
    Scam,
    Impersonation,
    DlpViolation,
    SuspiciousAttachment,
    UrlThreat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictReason {
    pub category: ThreatCategory,
    pub description: String,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpViolation {
    pub policy_id: String,
    pub policy_name: String,
    pub severity: DlpSeverity,
    pub matches: Vec<DlpMatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DlpSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpMatch {
    pub pattern_name: String,
    pub location: String,
    pub snippet: String,
}

// =============================================================================
// Authentication Results
// =============================================================================

/// Email authentication results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthenticationResults {
    pub spf: AuthResult,
    pub dkim: AuthResult,
    pub dmarc: AuthResult,
    pub arc: AuthResult,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthResult {
    pub result: AuthStatus,
    pub domain: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AuthStatus {
    #[default]
    None,
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
}

// =============================================================================
// Email Security Gateway Service
// =============================================================================

/// Email Security Gateway main service
pub struct EmailSecurityGateway {
    config: GatewayConfig,
    spam_classifier: spam::SpamClassifier,
    phishing_detector: phishing::PhishingDetector,
    reputation_service: reputation::ReputationService,
    attachment_analyzer: attachments::AttachmentAnalyzer,
    sandbox: sandbox::MalwareSandbox,
    bec_detector: bec::BecDetector,
    dlp_engine: dlp::DlpEngine,
    stats: GatewayStats,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Spam score threshold for quarantine
    pub spam_threshold: f64,
    /// Phishing score threshold for reject
    pub phishing_threshold: f64,
    /// Enable sandbox for suspicious attachments
    pub enable_sandbox: bool,
    /// Enable BEC detection
    pub enable_bec: bool,
    /// Enable DLP scanning
    pub enable_dlp: bool,
    /// Enable URL rewriting
    pub enable_url_rewriting: bool,
    /// Maximum message size (bytes)
    pub max_message_size: usize,
    /// Maximum attachment size (bytes)
    pub max_attachment_size: usize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            spam_threshold: 5.0,
            phishing_threshold: 7.0,
            enable_sandbox: true,
            enable_bec: true,
            enable_dlp: true,
            enable_url_rewriting: true,
            max_message_size: 50 * 1024 * 1024, // 50MB
            max_attachment_size: 25 * 1024 * 1024, // 25MB
        }
    }
}

#[derive(Debug, Default)]
pub struct GatewayStats {
    pub messages_processed: std::sync::atomic::AtomicU64,
    pub messages_delivered: std::sync::atomic::AtomicU64,
    pub messages_quarantined: std::sync::atomic::AtomicU64,
    pub messages_rejected: std::sync::atomic::AtomicU64,
    pub spam_detected: std::sync::atomic::AtomicU64,
    pub phishing_detected: std::sync::atomic::AtomicU64,
    pub malware_detected: std::sync::atomic::AtomicU64,
    pub bec_detected: std::sync::atomic::AtomicU64,
    pub dlp_violations: std::sync::atomic::AtomicU64,
}

impl EmailSecurityGateway {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            spam_classifier: spam::SpamClassifier::new(),
            phishing_detector: phishing::PhishingDetector::new(),
            reputation_service: reputation::ReputationService::new(),
            attachment_analyzer: attachments::AttachmentAnalyzer::new(),
            sandbox: sandbox::MalwareSandbox::new(),
            bec_detector: bec::BecDetector::new(),
            dlp_engine: dlp::DlpEngine::new(),
            stats: GatewayStats::default(),
        }
    }
    
    /// Process an email message through all security checks
    pub async fn process(&self, message: &EmailMessage) -> EmailVerdict {
        use std::sync::atomic::Ordering;
        
        let start = std::time::Instant::now();
        self.stats.messages_processed.fetch_add(1, Ordering::Relaxed);
        
        let mut verdict = EmailVerdict {
            message_id: message.id.clone(),
            action: VerdictAction::Deliver,
            overall_score: 0.0,
            spam_score: 0.0,
            phishing_score: 0.0,
            malware_score: 0.0,
            bec_score: 0.0,
            dlp_violations: Vec::new(),
            categories: Vec::new(),
            reasons: Vec::new(),
            processing_time_ms: 0,
        };
        
        // 1. Check sender reputation
        let reputation = self.reputation_service.check(&message.envelope).await;
        if reputation.is_blocked() {
            verdict.action = VerdictAction::Reject;
            verdict.reasons.push(VerdictReason {
                category: ThreatCategory::Spam,
                description: "Sender IP is blocklisted".to_string(),
                confidence: 1.0,
                source: "reputation".to_string(),
            });
            return verdict;
        }
        
        // 2. Spam classification
        let spam_result = self.spam_classifier.classify(message).await;
        verdict.spam_score = spam_result.score;
        if spam_result.is_spam {
            self.stats.spam_detected.fetch_add(1, Ordering::Relaxed);
            verdict.categories.push(ThreatCategory::Spam);
            verdict.reasons.extend(spam_result.reasons);
        }
        
        // 3. Phishing detection
        let phishing_result = self.phishing_detector.detect(message).await;
        verdict.phishing_score = phishing_result.score;
        if phishing_result.is_phishing {
            self.stats.phishing_detected.fetch_add(1, Ordering::Relaxed);
            verdict.categories.push(ThreatCategory::Phishing);
            verdict.reasons.extend(phishing_result.reasons);
        }
        
        // 4. Attachment analysis
        for attachment in &message.attachments {
            let attachment_result = self.attachment_analyzer.analyze(attachment).await;
            
            if attachment_result.is_malicious {
                self.stats.malware_detected.fetch_add(1, Ordering::Relaxed);
                verdict.malware_score = 10.0;
                verdict.categories.push(ThreatCategory::Malware);
                verdict.reasons.push(VerdictReason {
                    category: ThreatCategory::Malware,
                    description: format!("Malicious attachment: {}", attachment.filename),
                    confidence: attachment_result.confidence,
                    source: "attachment_analyzer".to_string(),
                });
            }
            
            // Sandbox suspicious attachments
            if self.config.enable_sandbox && attachment_result.needs_sandbox {
                let sandbox_result = self.sandbox.analyze(attachment).await;
                if sandbox_result.is_malicious {
                    verdict.malware_score = 10.0;
                    verdict.categories.push(ThreatCategory::Malware);
                }
            }
        }
        
        // 5. BEC detection
        if self.config.enable_bec {
            let bec_result = self.bec_detector.detect(message).await;
            verdict.bec_score = bec_result.score;
            if bec_result.is_bec {
                self.stats.bec_detected.fetch_add(1, Ordering::Relaxed);
                verdict.categories.push(ThreatCategory::Bec);
                verdict.reasons.extend(bec_result.reasons);
            }
        }
        
        // 6. DLP scanning (outbound)
        if self.config.enable_dlp {
            let dlp_result = self.dlp_engine.scan(message).await;
            if !dlp_result.violations.is_empty() {
                self.stats.dlp_violations.fetch_add(1, Ordering::Relaxed);
                verdict.categories.push(ThreatCategory::DlpViolation);
                verdict.dlp_violations = dlp_result.violations;
            }
        }
        
        // Calculate overall score and determine action
        verdict.overall_score = verdict.spam_score 
            + verdict.phishing_score * 1.5 
            + verdict.malware_score * 2.0 
            + verdict.bec_score * 1.5;
        
        verdict.action = self.determine_action(&verdict);
        
        // Update stats
        match verdict.action {
            VerdictAction::Deliver | VerdictAction::DeliverModified => {
                self.stats.messages_delivered.fetch_add(1, Ordering::Relaxed);
            }
            VerdictAction::Quarantine => {
                self.stats.messages_quarantined.fetch_add(1, Ordering::Relaxed);
            }
            VerdictAction::Reject | VerdictAction::Drop => {
                self.stats.messages_rejected.fetch_add(1, Ordering::Relaxed);
            }
            VerdictAction::Defer => {}
        }
        
        verdict.processing_time_ms = start.elapsed().as_millis() as u64;
        verdict
    }
    
    fn determine_action(&self, verdict: &EmailVerdict) -> VerdictAction {
        // Malware always rejects
        if verdict.malware_score >= 5.0 {
            return VerdictAction::Reject;
        }
        
        // High phishing score rejects
        if verdict.phishing_score >= self.config.phishing_threshold {
            return VerdictAction::Reject;
        }
        
        // BEC with high confidence quarantines
        if verdict.bec_score >= 7.0 {
            return VerdictAction::Quarantine;
        }
        
        // DLP violations quarantine
        if !verdict.dlp_violations.is_empty() {
            let has_critical = verdict.dlp_violations.iter()
                .any(|v| v.severity == DlpSeverity::Critical);
            if has_critical {
                return VerdictAction::Reject;
            }
            return VerdictAction::Quarantine;
        }
        
        // Spam quarantines
        if verdict.spam_score >= self.config.spam_threshold {
            return VerdictAction::Quarantine;
        }
        
        // URL rewriting for suspicious but not blocked
        if verdict.phishing_score > 3.0 && self.config.enable_url_rewriting {
            return VerdictAction::DeliverModified;
        }
        
        VerdictAction::Deliver
    }
    
    /// Get statistics snapshot
    pub fn get_stats(&self) -> GatewayStatsSnapshot {
        use std::sync::atomic::Ordering;
        
        GatewayStatsSnapshot {
            messages_processed: self.stats.messages_processed.load(Ordering::Relaxed),
            messages_delivered: self.stats.messages_delivered.load(Ordering::Relaxed),
            messages_quarantined: self.stats.messages_quarantined.load(Ordering::Relaxed),
            messages_rejected: self.stats.messages_rejected.load(Ordering::Relaxed),
            spam_detected: self.stats.spam_detected.load(Ordering::Relaxed),
            phishing_detected: self.stats.phishing_detected.load(Ordering::Relaxed),
            malware_detected: self.stats.malware_detected.load(Ordering::Relaxed),
            bec_detected: self.stats.bec_detected.load(Ordering::Relaxed),
            dlp_violations: self.stats.dlp_violations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewayStatsSnapshot {
    pub messages_processed: u64,
    pub messages_delivered: u64,
    pub messages_quarantined: u64,
    pub messages_rejected: u64,
    pub spam_detected: u64,
    pub phishing_detected: u64,
    pub malware_detected: u64,
    pub bec_detected: u64,
    pub dlp_violations: u64,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_verdict_action_determination() {
        let gateway = EmailSecurityGateway::new(GatewayConfig::default());
        
        // High spam score should quarantine
        let verdict = EmailVerdict {
            message_id: "test".to_string(),
            action: VerdictAction::Deliver,
            overall_score: 6.0,
            spam_score: 6.0,
            phishing_score: 0.0,
            malware_score: 0.0,
            bec_score: 0.0,
            dlp_violations: vec![],
            categories: vec![ThreatCategory::Spam],
            reasons: vec![],
            processing_time_ms: 0,
        };
        
        assert_eq!(gateway.determine_action(&verdict), VerdictAction::Quarantine);
    }
}
