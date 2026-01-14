//! Email Processing Pipeline
//!
//! Unified pipeline orchestrating all security checks.

use crate::{EmailMessage, EmailVerdict, VerdictAction, ThreatCategory, VerdictReason};
use std::sync::Arc;

/// Email security pipeline
pub struct EmailPipeline {
    /// Spam classifier
    spam: crate::spam::SpamClassifier,
    /// Phishing detector
    phishing: crate::phishing::PhishingDetector,
    /// Reputation service
    reputation: crate::reputation::ReputationService,
    /// Attachment analyzer
    attachments: crate::attachments::AttachmentAnalyzer,
    /// BEC detector
    bec: crate::bec::BecDetector,
    /// DNS blocklists
    blocklists: crate::blocklists::DnsBlocklists,
    /// Email authenticator
    auth: crate::auth::EmailAuthenticator,
    /// URL rewriter
    url_rewriter: Option<crate::urlrewrite::UrlRewriter>,
    /// Pipeline config
    config: PipelineConfig,
}

#[derive(Clone)]
pub struct PipelineConfig {
    /// Spam score threshold
    pub spam_threshold: f64,
    /// Phishing score threshold
    pub phishing_threshold: f64,
    /// Enable sandbox for attachments
    pub enable_sandbox: bool,
    /// Enable URL rewriting
    pub enable_url_rewriting: bool,
    /// Enable BEC detection
    pub enable_bec: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            spam_threshold: 50.0,
            phishing_threshold: 50.0,
            enable_sandbox: true,
            enable_url_rewriting: true,
            enable_bec: true,
        }
    }
}

impl EmailPipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            spam: crate::spam::SpamClassifier::new(),
            phishing: crate::phishing::PhishingDetector::new(),
            reputation: crate::reputation::ReputationService::new(),
            attachments: crate::attachments::AttachmentAnalyzer::new(),
            bec: crate::bec::BecDetector::new(),
            blocklists: crate::blocklists::DnsBlocklists::new(),
            auth: crate::auth::EmailAuthenticator::new(),
            url_rewriter: None,
            config,
        }
    }
    
    /// Process email through all security layers
    pub async fn process(&self, message: &EmailMessage) -> EmailVerdict {
        let start = std::time::Instant::now();
        
        let mut verdict = EmailVerdict {
            message_id: message.id.clone(),
            action: VerdictAction::Deliver,
            overall_score: 0.0,
            spam_score: 0.0,
            phishing_score: 0.0,
            malware_score: 0.0,
            bec_score: 0.0,
            dlp_violations: vec![],
            categories: vec![],
            reasons: vec![],
            processing_time_ms: 0,
        };
        
        // Stage 1: Connection-level checks
        let stage1 = self.stage_connection(&message.envelope).await;
        if stage1.should_reject {
            verdict.action = VerdictAction::Reject;
            verdict.reasons.extend(stage1.reasons);
            verdict.processing_time_ms = start.elapsed().as_millis() as u64;
            return verdict;
        }
        verdict.reasons.extend(stage1.reasons);
        verdict.overall_score += stage1.score;
        
        // Stage 2: Authentication
        let auth_results = self.auth.authenticate(
            message.envelope.client_ip,
            &message.envelope.mail_from,
            &message.headers.from,
            message.headers.dkim_signature.as_deref(),
        ).await;
        
        if auth_results.dmarc.result == crate::AuthStatus::Fail {
            verdict.reasons.push(VerdictReason {
                category: ThreatCategory::Phishing,
                description: "DMARC authentication failed".to_string(),
                confidence: 0.9,
                source: "auth".to_string(),
            });
            verdict.overall_score += 20.0;
        }
        
        // Stage 3: Content analysis (parallel)
        let (spam_result, phishing_result, bec_result) = tokio::join!(
            self.spam.classify(message),
            self.phishing.detect(message),
            async {
                if self.config.enable_bec {
                    Some(self.bec.detect(message).await)
                } else {
                    None
                }
            }
        );
        
        // Process spam result
        verdict.spam_score = spam_result.score;
        if spam_result.is_spam {
            verdict.categories.push(ThreatCategory::Spam);
        }
        verdict.reasons.extend(spam_result.reasons);
        
        // Process phishing result
        verdict.phishing_score = phishing_result.score;
        if phishing_result.is_phishing {
            verdict.categories.push(ThreatCategory::Phishing);
        }
        verdict.reasons.extend(phishing_result.reasons);
        
        // Process BEC result
        if let Some(bec) = bec_result {
            verdict.bec_score = bec.score;
            if bec.is_bec {
                verdict.categories.push(ThreatCategory::Bec);
            }
            verdict.reasons.extend(bec.reasons);
        }
        
        // Stage 4: Attachment analysis
        for attachment in &message.attachments {
            let result = self.attachments.analyze(attachment).await;
            
            if result.is_malicious {
                verdict.malware_score = 100.0;
                verdict.categories.push(ThreatCategory::Malware);
                verdict.reasons.push(VerdictReason {
                    category: ThreatCategory::Malware,
                    description: format!("Malicious attachment: {}", attachment.filename),
                    confidence: result.confidence,
                    source: "attachment".to_string(),
                });
            }
        }
        
        // Calculate overall score
        verdict.overall_score =
            verdict.spam_score * 0.3 +
            verdict.phishing_score * 0.4 +
            verdict.malware_score * 0.5 +
            verdict.bec_score * 0.3;
        
        // Determine action
        verdict.action = self.determine_action(&verdict);
        verdict.processing_time_ms = start.elapsed().as_millis() as u64;
        
        verdict
    }
    
    async fn stage_connection(&self, envelope: &crate::EmailEnvelope) -> StageResult {
        let mut result = StageResult::default();
        
        // Check reputation
        let reputation = self.reputation.check(envelope).await;
        if reputation.is_blocked() {
            result.should_reject = true;
            result.reasons.push(VerdictReason {
                category: ThreatCategory::Spam,
                description: "Sender IP blocklisted".to_string(),
                confidence: 1.0,
                source: "reputation".to_string(),
            });
            return result;
        }
        
        // Check DNS blocklists
        let dnsbl_results = self.blocklists.check_all(envelope.client_ip).await;
        let dnsbl_score = self.blocklists.calculate_score(&dnsbl_results);
        
        if dnsbl_score > 0.0 {
            result.score += dnsbl_score;
            for (name, check) in dnsbl_results {
                if check.listed {
                    result.reasons.push(VerdictReason {
                        category: ThreatCategory::Spam,
                        description: format!("Listed in {}", name),
                        confidence: 0.8,
                        source: "dnsbl".to_string(),
                    });
                }
            }
        }
        
        result
    }
    
    fn determine_action(&self, verdict: &EmailVerdict) -> VerdictAction {
        // Malware always rejects
        if verdict.malware_score >= 50.0 {
            return VerdictAction::Reject;
        }
        
        // High phishing score rejects
        if verdict.phishing_score >= self.config.phishing_threshold {
            return VerdictAction::Reject;
        }
        
        // High BEC score quarantines
        if verdict.bec_score >= 70.0 {
            return VerdictAction::Quarantine;
        }
        
        // Spam quarantines
        if verdict.spam_score >= self.config.spam_threshold {
            return VerdictAction::Quarantine;
        }
        
        // Suspicious content may need URL rewriting
        if verdict.phishing_score > 25.0 && self.config.enable_url_rewriting {
            return VerdictAction::DeliverModified;
        }
        
        VerdictAction::Deliver
    }
}

#[derive(Default)]
struct StageResult {
    should_reject: bool,
    score: f64,
    reasons: Vec<VerdictReason>,
}
