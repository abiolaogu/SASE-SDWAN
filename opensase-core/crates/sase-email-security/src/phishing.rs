//! Phishing Detection
//!
//! Advanced phishing detection using URL analysis, brand spoofing, and visual similarity.

use crate::{EmailMessage, VerdictReason, ThreatCategory, ExtractedUrl};
use std::collections::{HashMap, HashSet};

/// Phishing detector
pub struct PhishingDetector {
    /// Known phishing domains
    phishing_domains: HashSet<String>,
    /// Protected brands
    protected_brands: HashMap<String, BrandInfo>,
    /// Suspicious TLDs
    suspicious_tlds: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct PhishingResult {
    pub score: f64,
    pub is_phishing: bool,
    pub reasons: Vec<VerdictReason>,
    pub urls_analyzed: Vec<UrlAnalysis>,
}

#[derive(Debug, Clone)]
pub struct UrlAnalysis {
    pub url: String,
    pub is_suspicious: bool,
    pub reasons: Vec<String>,
    pub resolved_url: Option<String>,
}

#[derive(Debug, Clone)]
struct BrandInfo {
    name: String,
    domains: Vec<String>,
    keywords: Vec<String>,
    logo_hash: Option<String>,
}

impl PhishingDetector {
    pub fn new() -> Self {
        Self {
            phishing_domains: default_phishing_domains(),
            protected_brands: default_protected_brands(),
            suspicious_tlds: default_suspicious_tlds(),
        }
    }
    
    /// Detect phishing in an email
    pub async fn detect(&self, message: &EmailMessage) -> PhishingResult {
        let mut result = PhishingResult {
            score: 0.0,
            is_phishing: false,
            reasons: Vec::new(),
            urls_analyzed: Vec::new(),
        };
        
        // 1. Check sender spoofing
        let sender_score = self.check_sender_spoofing(message, &mut result.reasons);
        result.score += sender_score;
        
        // 2. Analyze URLs
        let url_score = self.analyze_urls(message, &mut result).await;
        result.score += url_score;
        
        // 3. Check for brand impersonation in content
        let brand_score = self.check_brand_impersonation(message, &mut result.reasons);
        result.score += brand_score;
        
        // 4. Check for urgency/fear tactics
        let urgency_score = self.check_urgency_tactics(message, &mut result.reasons);
        result.score += urgency_score;
        
        // 5. Check for credential harvesting indicators
        let credential_score = self.check_credential_harvesting(message, &mut result.reasons);
        result.score += credential_score;
        
        // Threshold check
        result.is_phishing = result.score >= 5.0;
        
        result
    }
    
    fn check_sender_spoofing(&self, message: &EmailMessage, reasons: &mut Vec<VerdictReason>) -> f64 {
        let mut score = 0.0;
        
        let from_domain = extract_domain(&message.headers.from);
        let envelope_domain = extract_domain(&message.envelope.mail_from);
        
        // Check if From domain is different from envelope
        if !from_domain.is_empty() && !envelope_domain.is_empty() && from_domain != envelope_domain {
            score += 2.0;
            reasons.push(VerdictReason {
                category: ThreatCategory::Phishing,
                description: format!(
                    "From domain ({}) differs from envelope ({})",
                    from_domain, envelope_domain
                ),
                confidence: 0.8,
                source: "sender_spoofing".to_string(),
            });
        }
        
        // Check for brand words in display name but different domain
        for (brand_key, brand_info) in &self.protected_brands {
            let from_lower = message.headers.from.to_lowercase();
            
            // Check if brand name appears in display name
            if from_lower.contains(&brand_info.name.to_lowercase()) {
                // But domain is not official
                let is_official = brand_info.domains.iter()
                    .any(|d| from_domain.ends_with(d));
                
                if !is_official {
                    score += 4.0;
                    reasons.push(VerdictReason {
                        category: ThreatCategory::Impersonation,
                        description: format!(
                            "Sender impersonates {} but uses domain {}",
                            brand_info.name, from_domain
                        ),
                        confidence: 0.9,
                        source: "brand_spoofing".to_string(),
                    });
                }
            }
        }
        
        score
    }
    
    async fn analyze_urls(&self, message: &EmailMessage, result: &mut PhishingResult) -> f64 {
        let mut score = 0.0;
        
        for url in &message.body.urls {
            let mut analysis = UrlAnalysis {
                url: url.url.clone(),
                is_suspicious: false,
                reasons: Vec::new(),
                resolved_url: None,
            };
            
            // Check domain against known phishing
            if let Some(domain) = extract_url_domain(&url.url) {
                if self.phishing_domains.contains(&domain) {
                    score += 10.0;
                    analysis.is_suspicious = true;
                    analysis.reasons.push("Known phishing domain".to_string());
                    result.reasons.push(VerdictReason {
                        category: ThreatCategory::Phishing,
                        description: format!("Known phishing domain: {}", domain),
                        confidence: 0.99,
                        source: "phishing_db".to_string(),
                    });
                }
                
                // Check suspicious TLD
                let tld = domain.rsplit('.').next().unwrap_or("").to_lowercase();
                if self.suspicious_tlds.contains(&tld) {
                    score += 1.0;
                    analysis.reasons.push(format!("Suspicious TLD: .{}", tld));
                }
                
                // Check for typosquatting
                for (_, brand_info) in &self.protected_brands {
                    for official_domain in &brand_info.domains {
                        if is_typosquat(&domain, official_domain) {
                            score += 5.0;
                            analysis.is_suspicious = true;
                            analysis.reasons.push(format!(
                                "Typosquatting of {}", official_domain
                            ));
                            result.reasons.push(VerdictReason {
                                category: ThreatCategory::Phishing,
                                description: format!(
                                    "URL typosquats {}: {}", official_domain, domain
                                ),
                                confidence: 0.9,
                                source: "typosquat".to_string(),
                            });
                        }
                    }
                }
            }
            
            // Check for display text mismatch
            if let Some(display_text) = &url.display_text {
                if looks_like_url(display_text) {
                    let display_domain = extract_url_domain(display_text);
                    let actual_domain = extract_url_domain(&url.url);
                    
                    if display_domain != actual_domain {
                        score += 4.0;
                        analysis.is_suspicious = true;
                        analysis.reasons.push("Display text shows different URL".to_string());
                        result.reasons.push(VerdictReason {
                            category: ThreatCategory::Phishing,
                            description: "Link text shows different URL than actual link".to_string(),
                            confidence: 0.95,
                            source: "link_mismatch".to_string(),
                        });
                    }
                }
            }
            
            // Check for suspicious URL patterns
            let url_lower = url.url.to_lowercase();
            
            // Login/signin in URL path
            if url_lower.contains("login") || url_lower.contains("signin") || 
               url_lower.contains("account") || url_lower.contains("verify") {
                score += 0.5;
                analysis.reasons.push("Contains login-related path".to_string());
            }
            
            // IP address instead of domain
            if regex::Regex::new(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                .map(|r| r.is_match(&url.url))
                .unwrap_or(false) 
            {
                score += 2.0;
                analysis.is_suspicious = true;
                analysis.reasons.push("Uses IP address instead of domain".to_string());
            }
            
            // Data URI or javascript URI
            if url_lower.starts_with("data:") || url_lower.starts_with("javascript:") {
                score += 3.0;
                analysis.is_suspicious = true;
                analysis.reasons.push("Suspicious URI scheme".to_string());
            }
            
            result.urls_analyzed.push(analysis);
        }
        
        score
    }
    
    fn check_brand_impersonation(&self, message: &EmailMessage, reasons: &mut Vec<VerdictReason>) -> f64 {
        let mut score = 0.0;
        
        let body = message.body.text_plain.as_deref().unwrap_or("")
            .to_lowercase();
        let subject = message.headers.subject.to_lowercase();
        let combined = format!("{} {}", subject, body);
        
        for (_, brand_info) in &self.protected_brands {
            let brand_lower = brand_info.name.to_lowercase();
            
            // Check if brand mentioned but email not from official domain
            if combined.contains(&brand_lower) {
                let from_domain = extract_domain(&message.headers.from);
                let is_official = brand_info.domains.iter()
                    .any(|d| from_domain.ends_with(d));
                
                if !is_official && !from_domain.is_empty() {
                    // Check for brand-specific keywords
                    let keyword_matches = brand_info.keywords.iter()
                        .filter(|k| combined.contains(&k.to_lowercase()))
                        .count();
                    
                    if keyword_matches >= 2 {
                        score += 3.0;
                        reasons.push(VerdictReason {
                            category: ThreatCategory::Impersonation,
                            description: format!(
                                "Content impersonates {} with {} keyword matches",
                                brand_info.name, keyword_matches
                            ),
                            confidence: 0.8,
                            source: "brand_content".to_string(),
                        });
                    }
                }
            }
        }
        
        score
    }
    
    fn check_urgency_tactics(&self, message: &EmailMessage, reasons: &mut Vec<VerdictReason>) -> f64 {
        let mut score = 0.0;
        
        let body = message.body.text_plain.as_deref().unwrap_or("")
            .to_lowercase();
        let subject = message.headers.subject.to_lowercase();
        let combined = format!("{} {}", subject, body);
        
        let urgency_phrases = [
            "immediate action required",
            "your account will be suspended",
            "verify your identity immediately",
            "unauthorized access detected",
            "confirm your details within 24 hours",
            "your account has been compromised",
            "urgent security alert",
            "action required: verify",
            "failure to respond will result",
            "we have detected unusual activity",
        ];
        
        for phrase in urgency_phrases {
            if combined.contains(phrase) {
                score += 1.5;
                reasons.push(VerdictReason {
                    category: ThreatCategory::Phishing,
                    description: format!("Contains urgency tactic: '{}'", phrase),
                    confidence: 0.7,
                    source: "urgency".to_string(),
                });
            }
        }
        
        score
    }
    
    fn check_credential_harvesting(&self, message: &EmailMessage, reasons: &mut Vec<VerdictReason>) -> f64 {
        let mut score = 0.0;
        
        let body = message.body.text_plain.as_deref().unwrap_or("")
            .to_lowercase();
        
        let credential_phrases = [
            "enter your password",
            "verify your credentials",
            "update your payment information",
            "confirm your credit card",
            "enter your social security",
            "provide your bank details",
            "reply with your password",
        ];
        
        for phrase in credential_phrases {
            if body.contains(phrase) {
                score += 3.0;
                reasons.push(VerdictReason {
                    category: ThreatCategory::Phishing,
                    description: format!("Requests credentials: '{}'", phrase),
                    confidence: 0.9,
                    source: "credential_request".to_string(),
                });
            }
        }
        
        score
    }
}

impl Default for PhishingDetector {
    fn default() -> Self {
        Self::new()
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

fn extract_url_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    
    without_scheme
        .split('/')
        .next()
        .map(|s| s.split(':').next().unwrap_or(s).to_lowercase())
}

fn looks_like_url(text: &str) -> bool {
    text.starts_with("http://") || 
    text.starts_with("https://") ||
    text.starts_with("www.")
}

fn is_typosquat(candidate: &str, target: &str) -> bool {
    let candidate = candidate.to_lowercase();
    let target = target.to_lowercase();
    
    if candidate == target {
        return false;
    }
    
    // Check edit distance
    if levenshtein_distance(&candidate, &target) <= 2 {
        return true;
    }
    
    // Check for common typosquat patterns
    let patterns = [
        // Character substitution
        ("o", "0"), ("l", "1"), ("e", "3"), ("a", "4"),
        // Character addition
        ("", "w"), ("", "-"),
    ];
    
    for (from, to) in patterns {
        if candidate.replace(to, from) == target {
            return true;
        }
    }
    
    false
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();
    
    if m == 0 { return n; }
    if n == 0 { return m; }
    
    let mut dp = vec![vec![0; n + 1]; m + 1];
    
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a_chars[i-1] == b_chars[j-1] { 0 } else { 1 };
            dp[i][j] = (dp[i-1][j] + 1)
                .min(dp[i][j-1] + 1)
                .min(dp[i-1][j-1] + cost);
        }
    }
    
    dp[m][n]
}

fn default_phishing_domains() -> HashSet<String> {
    // These would come from threat intel in production
    HashSet::new()
}

fn default_protected_brands() -> HashMap<String, BrandInfo> {
    let mut brands = HashMap::new();
    
    brands.insert("microsoft".to_string(), BrandInfo {
        name: "Microsoft".to_string(),
        domains: vec!["microsoft.com".to_string(), "office.com".to_string(), "live.com".to_string()],
        keywords: vec!["office 365".to_string(), "outlook".to_string(), "teams".to_string(), "azure".to_string()],
        logo_hash: None,
    });
    
    brands.insert("google".to_string(), BrandInfo {
        name: "Google".to_string(),
        domains: vec!["google.com".to_string(), "gmail.com".to_string(), "googleapis.com".to_string()],
        keywords: vec!["gmail".to_string(), "drive".to_string(), "docs".to_string()],
        logo_hash: None,
    });
    
    brands.insert("apple".to_string(), BrandInfo {
        name: "Apple".to_string(),
        domains: vec!["apple.com".to_string(), "icloud.com".to_string()],
        keywords: vec!["icloud".to_string(), "apple id".to_string(), "itunes".to_string()],
        logo_hash: None,
    });
    
    brands.insert("amazon".to_string(), BrandInfo {
        name: "Amazon".to_string(),
        domains: vec!["amazon.com".to_string(), "aws.amazon.com".to_string()],
        keywords: vec!["prime".to_string(), "aws".to_string(), "kindle".to_string()],
        logo_hash: None,
    });
    
    brands.insert("paypal".to_string(), BrandInfo {
        name: "PayPal".to_string(),
        domains: vec!["paypal.com".to_string()],
        keywords: vec!["payment".to_string(), "transaction".to_string(), "balance".to_string()],
        logo_hash: None,
    });
    
    brands
}

fn default_suspicious_tlds() -> HashSet<String> {
    [
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
        "link", "buzz", "cam", "icu", "surf", "monster", "uno",
    ].iter().map(|s| s.to_string()).collect()
}
