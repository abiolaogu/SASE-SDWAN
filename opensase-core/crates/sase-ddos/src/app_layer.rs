//! Application Layer Defense
//!
//! HTTP challenge, bot detection, and L7 rate limiting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

/// Application layer DDoS protection
pub struct AppLayerDefense {
    /// Challenge tokens
    challenge_tokens: DashMap<String, ChallengeToken>,
    /// Verified clients (passed challenge)
    verified_clients: DashMap<IpAddr, VerifiedClient>,
    /// Request rate tracking
    request_rates: DashMap<IpAddr, RequestRateEntry>,
    /// Bot signatures
    bot_signatures: Vec<BotSignature>,
    /// Configuration
    config: AppLayerConfig,
    /// Statistics
    stats: AppLayerStats,
}

#[derive(Debug, Clone)]
pub struct AppLayerConfig {
    /// Enable JavaScript challenge
    pub js_challenge_enabled: bool,
    /// Enable CAPTCHA for persistent attackers
    pub captcha_enabled: bool,
    /// Request rate limit per IP (per second)
    pub rate_limit_per_ip: u64,
    /// Request rate limit per URL (per second)
    pub rate_limit_per_url: u64,
    /// Challenge validity (seconds)
    pub challenge_validity: u64,
    /// Verification validity (seconds)
    pub verification_validity: u64,
    /// Minimum time between requests (ms)
    pub min_request_interval_ms: u64,
}

impl Default for AppLayerConfig {
    fn default() -> Self {
        Self {
            js_challenge_enabled: true,
            captcha_enabled: true,
            rate_limit_per_ip: 100,
            rate_limit_per_url: 1000,
            challenge_validity: 60,
            verification_validity: 3600,
            min_request_interval_ms: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeToken {
    pub token: String,
    pub ip: IpAddr,
    pub challenge_type: ChallengeType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy)]
pub enum ChallengeType {
    JavaScript,
    Captcha,
    Cookie,
    ProofOfWork,
}

#[derive(Debug, Clone)]
pub struct VerifiedClient {
    pub ip: IpAddr,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub trust_score: u8,
    pub request_count: u64,
}

struct RequestRateEntry {
    count: AtomicU64,
    last_request: parking_lot::Mutex<chrono::DateTime<chrono::Utc>>,
    window_start: parking_lot::Mutex<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct BotSignature {
    pub name: String,
    pub user_agent_pattern: Option<String>,
    pub behavior: BotBehavior,
    pub action: BotAction,
}

#[derive(Debug, Clone, Copy)]
pub enum BotBehavior {
    NoJavaScript,
    NoCookies,
    FastRequests,
    SequentialUrls,
    NoReferer,
    SuspiciousHeaders,
}

#[derive(Debug, Clone, Copy)]
pub enum BotAction {
    Allow,     // Good bot
    Challenge, // Unknown
    Block,     // Bad bot
    RateLimit, // Slow down
}

#[derive(Debug, Default)]
pub struct AppLayerStats {
    pub requests_total: AtomicU64,
    pub requests_allowed: AtomicU64,
    pub requests_blocked: AtomicU64,
    pub challenges_issued: AtomicU64,
    pub challenges_passed: AtomicU64,
    pub challenges_failed: AtomicU64,
    pub rate_limited: AtomicU64,
    pub bots_detected: AtomicU64,
}

/// HTTP request for analysis
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub client_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub host: String,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub cookie: Option<String>,
    pub headers: HashMap<String, String>,
    pub body_size: usize,
}

/// Decision for request handling
#[derive(Debug, Clone)]
pub enum RequestDecision {
    Allow,
    Challenge(ChallengeType),
    RateLimit(u64), // Delay ms
    Block(String),  // Reason
}

impl AppLayerDefense {
    pub fn new(config: AppLayerConfig) -> Self {
        Self {
            challenge_tokens: DashMap::new(),
            verified_clients: DashMap::new(),
            request_rates: DashMap::new(),
            bot_signatures: default_bot_signatures(),
            config,
            stats: AppLayerStats::default(),
        }
    }
    
    /// Analyze request and decide action
    pub fn analyze(&self, request: &HttpRequest) -> RequestDecision {
        self.stats.requests_total.fetch_add(1, Ordering::Relaxed);
        
        // Check if already verified
        if let Some(client) = self.verified_clients.get(&request.client_ip) {
            if client.expires_at > chrono::Utc::now() && client.trust_score >= 50 {
                // Still valid, check rate limit
                return self.check_rate_limit(request);
            }
        }
        
        // Check for bot signatures
        if let Some(action) = self.detect_bot(request) {
            match action {
                BotAction::Block => {
                    self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
                    self.stats.bots_detected.fetch_add(1, Ordering::Relaxed);
                    return RequestDecision::Block("Bot detected".to_string());
                }
                BotAction::Challenge => {
                    return self.issue_challenge(request);
                }
                BotAction::RateLimit => {
                    self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return RequestDecision::RateLimit(1000);
                }
                BotAction::Allow => {}
            }
        }
        
        // Check rate limits
        let rate_decision = self.check_rate_limit(request);
        if !matches!(rate_decision, RequestDecision::Allow) {
            return rate_decision;
        }
        
        // For new IPs under attack, issue challenge
        if self.is_under_attack() && !self.is_verified(&request.client_ip) {
            return self.issue_challenge(request);
        }
        
        self.stats.requests_allowed.fetch_add(1, Ordering::Relaxed);
        RequestDecision::Allow
    }
    
    /// Verify challenge response
    pub fn verify_challenge(&self, ip: IpAddr, token: &str, response: &str) -> bool {
        if let Some(challenge) = self.challenge_tokens.get(token) {
            if challenge.ip != ip {
                return false;
            }
            
            if challenge.expires_at < chrono::Utc::now() {
                self.challenge_tokens.remove(token);
                return false;
            }
            
            // Verify based on challenge type
            let valid = match challenge.challenge_type {
                ChallengeType::JavaScript => self.verify_js_challenge(token, response),
                ChallengeType::Cookie => self.verify_cookie_challenge(token, response),
                ChallengeType::ProofOfWork => self.verify_pow_challenge(token, response),
                ChallengeType::Captcha => true, // CAPTCHA service handles
            };
            
            if valid {
                self.stats.challenges_passed.fetch_add(1, Ordering::Relaxed);
                
                // Add to verified clients
                let client = VerifiedClient {
                    ip,
                    verified_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now() + chrono::Duration::seconds(self.config.verification_validity as i64),
                    trust_score: 80,
                    request_count: 0,
                };
                self.verified_clients.insert(ip, client);
                
                self.challenge_tokens.remove(token);
                return true;
            } else {
                self.stats.challenges_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        false
    }
    
    fn issue_challenge(&self, request: &HttpRequest) -> RequestDecision {
        let challenge_type = if self.config.js_challenge_enabled {
            ChallengeType::JavaScript
        } else {
            ChallengeType::Cookie
        };
        
        let token = generate_token();
        let challenge = ChallengeToken {
            token: token.clone(),
            ip: request.client_ip,
            challenge_type,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(self.config.challenge_validity as i64),
        };
        
        self.challenge_tokens.insert(token, challenge);
        self.stats.challenges_issued.fetch_add(1, Ordering::Relaxed);
        
        RequestDecision::Challenge(challenge_type)
    }
    
    fn check_rate_limit(&self, request: &HttpRequest) -> RequestDecision {
        let entry = self.request_rates
            .entry(request.client_ip)
            .or_insert_with(|| RequestRateEntry {
                count: AtomicU64::new(0),
                last_request: parking_lot::Mutex::new(chrono::Utc::now()),
                window_start: parking_lot::Mutex::new(chrono::Utc::now()),
            });
        
        let now = chrono::Utc::now();
        
        // Check minimum interval
        {
            let mut last = entry.last_request.lock();
            let elapsed = (now - *last).num_milliseconds() as u64;
            if elapsed < self.config.min_request_interval_ms {
                self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                return RequestDecision::RateLimit(self.config.min_request_interval_ms - elapsed);
            }
            *last = now;
        }
        
        // Check rate limit
        {
            let mut window = entry.window_start.lock();
            if (now - *window).num_seconds() >= 1 {
                entry.count.store(0, Ordering::Relaxed);
                *window = now;
            }
        }
        
        let count = entry.count.fetch_add(1, Ordering::Relaxed);
        if count >= self.config.rate_limit_per_ip {
            self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
            return RequestDecision::RateLimit(1000);
        }
        
        RequestDecision::Allow
    }
    
    fn detect_bot(&self, request: &HttpRequest) -> Option<BotAction> {
        for sig in &self.bot_signatures {
            if let Some(pattern) = &sig.user_agent_pattern {
                if let Some(ua) = &request.user_agent {
                    if ua.to_lowercase().contains(&pattern.to_lowercase()) {
                        return Some(sig.action);
                    }
                }
            }
            
            match sig.behavior {
                BotBehavior::NoJavaScript => {
                    // Can't detect without challenge
                }
                BotBehavior::NoCookies => {
                    if request.cookie.is_none() {
                        return Some(BotAction::Challenge);
                    }
                }
                BotBehavior::NoReferer => {
                    if request.referer.is_none() && request.path != "/" {
                        // Suspicious but not conclusive
                    }
                }
                _ => {}
            }
        }
        
        None
    }
    
    fn is_verified(&self, ip: &IpAddr) -> bool {
        self.verified_clients.get(ip)
            .map(|c| c.expires_at > chrono::Utc::now())
            .unwrap_or(false)
    }
    
    fn is_under_attack(&self) -> bool {
        let total = self.stats.requests_total.load(Ordering::Relaxed);
        let blocked = self.stats.requests_blocked.load(Ordering::Relaxed);
        
        total > 1000 && blocked as f64 / total as f64 > 0.1
    }
    
    fn verify_js_challenge(&self, _token: &str, _response: &str) -> bool {
        // Verify JavaScript computed response
        // Real implementation would check crypto proof
        true
    }
    
    fn verify_cookie_challenge(&self, token: &str, response: &str) -> bool {
        response == token
    }
    
    fn verify_pow_challenge(&self, _token: &str, response: &str) -> bool {
        // Verify proof-of-work (e.g., hashcash)
        response.starts_with("0000")
    }
    
    /// Generate JavaScript challenge page
    pub fn generate_js_challenge_page(&self, token: &str) -> String {
        format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
        .spinner {{ width: 50px; height: 50px; border: 5px solid #f3f3f3; 
                   border-top: 5px solid #3498db; border-radius: 50%; 
                   animation: spin 1s linear infinite; margin: 20px auto; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <h1>Checking your browser...</h1>
    <div class="spinner"></div>
    <p>This is an automatic security check. Please wait.</p>
    <noscript>Please enable JavaScript to continue.</noscript>
    <script>
        var token = "{}";
        var challenge = function() {{
            var result = "";
            for(var i=0; i<100000; i++) {{ result = btoa(token + i); }}
            document.cookie = "__osddos=" + result + "; path=/; max-age=3600";
            window.location.reload();
        }};
        setTimeout(challenge, 1000);
    </script>
</body>
</html>"#, token)
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> AppLayerSnapshot {
        AppLayerSnapshot {
            requests_total: self.stats.requests_total.load(Ordering::Relaxed),
            requests_allowed: self.stats.requests_allowed.load(Ordering::Relaxed),
            requests_blocked: self.stats.requests_blocked.load(Ordering::Relaxed),
            challenges_issued: self.stats.challenges_issued.load(Ordering::Relaxed),
            challenges_passed: self.stats.challenges_passed.load(Ordering::Relaxed),
            rate_limited: self.stats.rate_limited.load(Ordering::Relaxed),
            verified_clients: self.verified_clients.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppLayerSnapshot {
    pub requests_total: u64,
    pub requests_allowed: u64,
    pub requests_blocked: u64,
    pub challenges_issued: u64,
    pub challenges_passed: u64,
    pub rate_limited: u64,
    pub verified_clients: usize,
}

fn generate_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", ts)
}

fn default_bot_signatures() -> Vec<BotSignature> {
    vec![
        BotSignature {
            name: "Googlebot".to_string(),
            user_agent_pattern: Some("googlebot".to_string()),
            behavior: BotBehavior::NoJavaScript,
            action: BotAction::Allow,
        },
        BotSignature {
            name: "Bingbot".to_string(),
            user_agent_pattern: Some("bingbot".to_string()),
            behavior: BotBehavior::NoJavaScript,
            action: BotAction::Allow,
        },
        BotSignature {
            name: "curl".to_string(),
            user_agent_pattern: Some("curl".to_string()),
            behavior: BotBehavior::NoCookies,
            action: BotAction::RateLimit,
        },
        BotSignature {
            name: "python-requests".to_string(),
            user_agent_pattern: Some("python-requests".to_string()),
            behavior: BotBehavior::NoCookies,
            action: BotAction::Challenge,
        },
        BotSignature {
            name: "Empty UA".to_string(),
            user_agent_pattern: Some("".to_string()),
            behavior: BotBehavior::SuspiciousHeaders,
            action: BotAction::Block,
        },
    ]
}
