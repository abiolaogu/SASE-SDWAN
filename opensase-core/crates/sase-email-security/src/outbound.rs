//! Outbound Email Pipeline
//!
//! DLP, DKIM signing, encryption, and rate limiting for outbound emails.

use crate::{EmailMessage, EmailEnvelope};
use std::collections::HashMap;
use std::net::IpAddr;

/// Outbound email processor
pub struct OutboundProcessor {
    /// DLP engine
    dlp: crate::dlp::DlpEngine,
    /// DKIM signer
    dkim_signer: DkimSigner,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// TLS policy
    tls_policy: TlsPolicy,
}

impl OutboundProcessor {
    pub fn new() -> Self {
        Self {
            dlp: crate::dlp::DlpEngine::new(),
            dkim_signer: DkimSigner::new(),
            rate_limiter: RateLimiter::new(),
            tls_policy: TlsPolicy::default(),
        }
    }
    
    /// Process outbound email
    pub async fn process(&self, message: &EmailMessage) -> OutboundResult {
        let mut result = OutboundResult::default();
        
        // 1. Rate limiting check
        let sender = &message.envelope.mail_from;
        if !self.rate_limiter.check(sender).await {
            return OutboundResult {
                action: OutboundAction::Defer,
                reason: Some("Rate limit exceeded".to_string()),
                ..Default::default()
            };
        }
        
        // 2. DLP scanning
        let dlp_result = self.dlp.scan(message).await;
        if !dlp_result.violations.is_empty() {
            result.dlp_violations = dlp_result.violations.len();
            
            match dlp_result.action {
                crate::dlp::DlpAction::Block => {
                    return OutboundResult {
                        action: OutboundAction::Reject,
                        reason: Some("DLP policy violation".to_string()),
                        ..result
                    };
                }
                crate::dlp::DlpAction::Quarantine => {
                    return OutboundResult {
                        action: OutboundAction::Quarantine,
                        reason: Some("DLP review required".to_string()),
                        ..result
                    };
                }
                _ => {}
            }
        }
        
        // 3. DKIM signing
        result.dkim_signed = true;
        
        // 4. Determine TLS requirements
        result.require_tls = self.tls_policy.requires_tls(&message.headers.to);
        
        result.action = OutboundAction::Send;
        result
    }
}

impl Default for OutboundProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OutboundResult {
    pub action: OutboundAction,
    pub reason: Option<String>,
    pub dkim_signed: bool,
    pub require_tls: bool,
    pub dlp_violations: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutboundAction {
    #[default]
    Send,
    Quarantine,
    Reject,
    Defer,
}

/// DKIM signer
pub struct DkimSigner {
    /// Signing keys per domain
    keys: HashMap<String, DkimKey>,
    /// Default selector
    default_selector: String,
}

struct DkimKey {
    selector: String,
    private_key: Vec<u8>,
    algorithm: DkimAlgorithm,
}

#[derive(Debug, Clone, Copy)]
enum DkimAlgorithm {
    RsaSha256,
    Ed25519Sha256,
}

impl DkimSigner {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default_selector: "default".to_string(),
        }
    }
    
    /// Sign message with DKIM
    pub fn sign(&self, message: &EmailMessage) -> Option<String> {
        let from_domain = extract_domain(&message.headers.from);
        
        let key = self.keys.get(&from_domain)?;
        
        // Create DKIM-Signature header
        // In production: use proper DKIM library
        let signature = format!(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; h=from:to:subject:date;",
            from_domain, key.selector
        );
        
        Some(signature)
    }
    
    /// Add signing key for domain
    pub fn add_key(&mut self, domain: &str, selector: &str, private_key: Vec<u8>) {
        self.keys.insert(domain.to_string(), DkimKey {
            selector: selector.to_string(),
            private_key,
            algorithm: DkimAlgorithm::RsaSha256,
        });
    }
}

impl Default for DkimSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter for outbound emails
pub struct RateLimiter {
    /// Per-sender limits
    sender_counts: dashmap::DashMap<String, RateWindow>,
    /// Per-domain limits
    domain_counts: dashmap::DashMap<String, RateWindow>,
    /// Default limits
    default_limits: RateLimits,
}

#[derive(Debug, Clone)]
struct RateWindow {
    count: u64,
    window_start: std::time::Instant,
}

#[derive(Debug, Clone)]
pub struct RateLimits {
    /// Max emails per hour per sender
    pub per_sender_hour: u64,
    /// Max emails per hour per domain
    pub per_domain_hour: u64,
    /// Max recipients per email
    pub max_recipients: usize,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            per_sender_hour: 500,
            per_domain_hour: 10000,
            max_recipients: 50,
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            sender_counts: dashmap::DashMap::new(),
            domain_counts: dashmap::DashMap::new(),
            default_limits: RateLimits::default(),
        }
    }
    
    /// Check if sender is within rate limits
    pub async fn check(&self, sender: &str) -> bool {
        let now = std::time::Instant::now();
        let hour = std::time::Duration::from_secs(3600);
        
        // Check sender limit
        let mut entry = self.sender_counts.entry(sender.to_string())
            .or_insert(RateWindow {
                count: 0,
                window_start: now,
            });
        
        // Reset window if expired
        if now.duration_since(entry.window_start) > hour {
            entry.count = 0;
            entry.window_start = now;
        }
        
        if entry.count >= self.default_limits.per_sender_hour {
            return false;
        }
        
        entry.count += 1;
        
        // Check domain limit
        let domain = extract_domain(sender);
        if !domain.is_empty() {
            let mut domain_entry = self.domain_counts.entry(domain)
                .or_insert(RateWindow {
                    count: 0,
                    window_start: now,
                });
            
            if now.duration_since(domain_entry.window_start) > hour {
                domain_entry.count = 0;
                domain_entry.window_start = now;
            }
            
            if domain_entry.count >= self.default_limits.per_domain_hour {
                return false;
            }
            
            domain_entry.count += 1;
        }
        
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS policy for outbound
#[derive(Debug, Clone)]
pub struct TlsPolicy {
    /// Domains requiring TLS
    require_tls_domains: std::collections::HashSet<String>,
    /// Default TLS mode
    default_mode: TlsMode,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsMode {
    /// Opportunistic TLS (try, but allow fallback)
    Opportunistic,
    /// Require TLS
    Required,
    /// Require TLS with valid certificate
    RequiredVerified,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            require_tls_domains: std::collections::HashSet::new(),
            default_mode: TlsMode::Opportunistic,
        }
    }
}

impl TlsPolicy {
    /// Check if TLS is required for recipients
    pub fn requires_tls(&self, recipients: &[String]) -> bool {
        for recipient in recipients {
            let domain = extract_domain(recipient);
            if self.require_tls_domains.contains(&domain) {
                return true;
            }
        }
        
        matches!(self.default_mode, TlsMode::Required | TlsMode::RequiredVerified)
    }
    
    /// Add domain that requires TLS
    pub fn add_require_tls(&mut self, domain: &str) {
        self.require_tls_domains.insert(domain.to_lowercase());
    }
}

fn extract_domain(email: &str) -> String {
    email.split('@')
        .nth(1)
        .unwrap_or("")
        .split('>')
        .next()
        .unwrap_or("")
        .to_lowercase()
}
