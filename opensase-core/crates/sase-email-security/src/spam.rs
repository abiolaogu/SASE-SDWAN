//! Spam Classification
//!
//! Multi-layer spam detection using Bayesian filtering, heuristics, and reputation.

use crate::{EmailMessage, VerdictReason, ThreatCategory};
use std::collections::{HashMap, HashSet};

/// Spam classifier using multiple detection methods
pub struct SpamClassifier {
    /// Word frequency database
    word_db: WordDatabase,
    /// Heuristic rules
    rules: Vec<SpamRule>,
    /// Spam keywords
    spam_keywords: HashSet<String>,
    /// Ham keywords (legitimate)
    ham_keywords: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct SpamResult {
    pub score: f64,
    pub is_spam: bool,
    pub reasons: Vec<VerdictReason>,
    pub method_scores: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
struct SpamRule {
    name: String,
    description: String,
    score: f64,
    check: RuleCheck,
}

#[derive(Debug, Clone)]
enum RuleCheck {
    SubjectContains(String),
    SubjectRegex(String),
    BodyContains(String),
    BodyRegex(String),
    HeaderMissing(String),
    HeaderContains(String, String),
    AttachmentType(String),
    UrlCount(u32),
    ImageHeavy,
}

/// Word frequency database for Bayesian filtering
struct WordDatabase {
    spam_words: HashMap<String, u64>,
    ham_words: HashMap<String, u64>,
    spam_total: u64,
    ham_total: u64,
}

impl SpamClassifier {
    pub fn new() -> Self {
        Self {
            word_db: WordDatabase::new(),
            rules: default_spam_rules(),
            spam_keywords: default_spam_keywords(),
            ham_keywords: default_ham_keywords(),
        }
    }
    
    /// Classify an email for spam
    pub async fn classify(&self, message: &EmailMessage) -> SpamResult {
        let mut result = SpamResult {
            score: 0.0,
            is_spam: false,
            reasons: Vec::new(),
            method_scores: HashMap::new(),
        };
        
        // 1. Bayesian classification
        let bayes_score = self.bayesian_score(message);
        result.method_scores.insert("bayesian".to_string(), bayes_score);
        result.score += bayes_score;
        
        // 2. Heuristic rules
        let heuristic_score = self.apply_heuristics(message, &mut result.reasons);
        result.method_scores.insert("heuristics".to_string(), heuristic_score);
        result.score += heuristic_score;
        
        // 3. Keyword analysis
        let keyword_score = self.keyword_analysis(message, &mut result.reasons);
        result.method_scores.insert("keywords".to_string(), keyword_score);
        result.score += keyword_score;
        
        // 4. Structure analysis
        let structure_score = self.structure_analysis(message, &mut result.reasons);
        result.method_scores.insert("structure".to_string(), structure_score);
        result.score += structure_score;
        
        // Threshold check
        result.is_spam = result.score >= 5.0;
        
        result
    }
    
    fn bayesian_score(&self, message: &EmailMessage) -> f64 {
        let text = format!(
            "{} {}",
            message.headers.subject,
            message.body.text_plain.as_deref().unwrap_or("")
        );
        
        self.word_db.calculate_spam_probability(&text) * 5.0
    }
    
    fn apply_heuristics(&self, message: &EmailMessage, reasons: &mut Vec<VerdictReason>) -> f64 {
        let mut score = 0.0;
        
        for rule in &self.rules {
            if self.check_rule(&rule.check, message) {
                score += rule.score;
                reasons.push(VerdictReason {
                    category: ThreatCategory::Spam,
                    description: rule.description.clone(),
                    confidence: 0.8,
                    source: format!("heuristic:{}", rule.name),
                });
            }
        }
        
        score
    }
    
    fn check_rule(&self, check: &RuleCheck, message: &EmailMessage) -> bool {
        match check {
            RuleCheck::SubjectContains(s) => {
                message.headers.subject.to_lowercase().contains(&s.to_lowercase())
            }
            RuleCheck::SubjectRegex(pattern) => {
                regex::Regex::new(pattern)
                    .map(|r| r.is_match(&message.headers.subject))
                    .unwrap_or(false)
            }
            RuleCheck::BodyContains(s) => {
                message.body.text_plain.as_ref()
                    .map(|b| b.to_lowercase().contains(&s.to_lowercase()))
                    .unwrap_or(false)
            }
            RuleCheck::BodyRegex(pattern) => {
                message.body.text_plain.as_ref()
                    .and_then(|b| regex::Regex::new(pattern).ok().map(|r| r.is_match(b)))
                    .unwrap_or(false)
            }
            RuleCheck::HeaderMissing(header) => {
                match header.to_lowercase().as_str() {
                    "message-id" => message.headers.message_id.is_none(),
                    "date" => message.headers.date.is_none(),
                    _ => false,
                }
            }
            RuleCheck::HeaderContains(header, value) => {
                match header.to_lowercase().as_str() {
                    "from" => message.headers.from.to_lowercase().contains(&value.to_lowercase()),
                    "subject" => message.headers.subject.to_lowercase().contains(&value.to_lowercase()),
                    _ => false,
                }
            }
            RuleCheck::AttachmentType(ext) => {
                message.attachments.iter().any(|a| 
                    a.filename.to_lowercase().ends_with(&format!(".{}", ext.to_lowercase()))
                )
            }
            RuleCheck::UrlCount(min) => {
                message.body.urls.len() as u32 >= *min
            }
            RuleCheck::ImageHeavy => {
                // Check if email is mostly images
                message.body.text_html.as_ref()
                    .map(|html| {
                        let img_count = html.matches("<img").count();
                        let text_len = html.len();
                        img_count > 3 && text_len < 500
                    })
                    .unwrap_or(false)
            }
        }
    }
    
    fn keyword_analysis(&self, message: &EmailMessage, reasons: &mut Vec<VerdictReason>) -> f64 {
        let text = format!(
            "{} {}",
            message.headers.subject,
            message.body.text_plain.as_deref().unwrap_or("")
        ).to_lowercase();
        
        let mut score = 0.0;
        let mut spam_matches = 0;
        let mut ham_matches = 0;
        
        for keyword in &self.spam_keywords {
            if text.contains(keyword) {
                spam_matches += 1;
            }
        }
        
        for keyword in &self.ham_keywords {
            if text.contains(keyword) {
                ham_matches += 1;
            }
        }
        
        if spam_matches > 3 {
            score += (spam_matches as f64) * 0.5;
            reasons.push(VerdictReason {
                category: ThreatCategory::Spam,
                description: format!("Contains {} spam keywords", spam_matches),
                confidence: 0.7,
                source: "keywords".to_string(),
            });
        }
        
        // Reduce score for legitimate keywords
        score -= (ham_matches as f64) * 0.3;
        
        score.max(0.0)
    }
    
    fn structure_analysis(&self, message: &EmailMessage, reasons: &mut Vec<VerdictReason>) -> f64 {
        let mut score = 0.0;
        
        // Check for suspicious patterns
        
        // All caps subject
        if message.headers.subject.chars().filter(|c| c.is_alphabetic()).all(|c| c.is_uppercase())
            && message.headers.subject.len() > 10 
        {
            score += 1.5;
            reasons.push(VerdictReason {
                category: ThreatCategory::Spam,
                description: "Subject is all uppercase".to_string(),
                confidence: 0.6,
                source: "structure".to_string(),
            });
        }
        
        // Too many URLs
        if message.body.urls.len() > 10 {
            score += 1.0;
            reasons.push(VerdictReason {
                category: ThreatCategory::Spam,
                description: format!("Contains {} URLs", message.body.urls.len()),
                confidence: 0.5,
                source: "structure".to_string(),
            });
        }
        
        // Empty body with attachments
        let body_len = message.body.text_plain.as_ref().map(|s| s.len()).unwrap_or(0);
        if body_len < 50 && !message.attachments.is_empty() {
            score += 0.5;
        }
        
        score
    }
    
    /// Train the classifier with a spam message
    pub fn train_spam(&mut self, message: &EmailMessage) {
        let text = format!(
            "{} {}",
            message.headers.subject,
            message.body.text_plain.as_deref().unwrap_or("")
        );
        self.word_db.add_spam(&text);
    }
    
    /// Train the classifier with a ham (legitimate) message
    pub fn train_ham(&mut self, message: &EmailMessage) {
        let text = format!(
            "{} {}",
            message.headers.subject,
            message.body.text_plain.as_deref().unwrap_or("")
        );
        self.word_db.add_ham(&text);
    }
}

impl Default for SpamClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl WordDatabase {
    fn new() -> Self {
        Self {
            spam_words: HashMap::new(),
            ham_words: HashMap::new(),
            spam_total: 0,
            ham_total: 0,
        }
    }
    
    fn add_spam(&mut self, text: &str) {
        for word in tokenize(text) {
            *self.spam_words.entry(word).or_insert(0) += 1;
            self.spam_total += 1;
        }
    }
    
    fn add_ham(&mut self, text: &str) {
        for word in tokenize(text) {
            *self.ham_words.entry(word).or_insert(0) += 1;
            self.ham_total += 1;
        }
    }
    
    fn calculate_spam_probability(&self, text: &str) -> f64 {
        if self.spam_total == 0 || self.ham_total == 0 {
            return 0.5; // Neutral when not trained
        }
        
        let words = tokenize(text);
        let mut log_prob_spam = 0.0f64;
        let mut log_prob_ham = 0.0f64;
        
        for word in words {
            let spam_count = *self.spam_words.get(&word).unwrap_or(&0) as f64;
            let ham_count = *self.ham_words.get(&word).unwrap_or(&0) as f64;
            
            // Laplace smoothing
            let p_word_spam = (spam_count + 1.0) / (self.spam_total as f64 + 2.0);
            let p_word_ham = (ham_count + 1.0) / (self.ham_total as f64 + 2.0);
            
            log_prob_spam += p_word_spam.ln();
            log_prob_ham += p_word_ham.ln();
        }
        
        // Convert back to probability
        let max_log = log_prob_spam.max(log_prob_ham);
        let prob_spam = (log_prob_spam - max_log).exp();
        let prob_ham = (log_prob_ham - max_log).exp();
        
        prob_spam / (prob_spam + prob_ham)
    }
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3 && w.len() <= 20)
        .map(|w| w.to_string())
        .collect()
}

fn default_spam_rules() -> Vec<SpamRule> {
    vec![
        SpamRule {
            name: "urgent_subject".to_string(),
            description: "Subject contains urgency keywords".to_string(),
            score: 1.5,
            check: RuleCheck::SubjectContains("urgent".to_string()),
        },
        SpamRule {
            name: "act_now".to_string(),
            description: "Contains 'act now' pressure".to_string(),
            score: 1.5,
            check: RuleCheck::BodyContains("act now".to_string()),
        },
        SpamRule {
            name: "free_money".to_string(),
            description: "Promises free money".to_string(),
            score: 2.0,
            check: RuleCheck::BodyContains("free money".to_string()),
        },
        SpamRule {
            name: "lottery_winner".to_string(),
            description: "Lottery scam indicators".to_string(),
            score: 3.0,
            check: RuleCheck::BodyContains("lottery winner".to_string()),
        },
        SpamRule {
            name: "nigerian_prince".to_string(),
            description: "419 scam indicators".to_string(),
            score: 4.0,
            check: RuleCheck::BodyRegex(r"(?i)prince|inheritance|million.{1,20}dollars".to_string()),
        },
        SpamRule {
            name: "missing_message_id".to_string(),
            description: "Missing Message-ID header".to_string(),
            score: 0.5,
            check: RuleCheck::HeaderMissing("message-id".to_string()),
        },
        SpamRule {
            name: "exe_attachment".to_string(),
            description: "Contains executable attachment".to_string(),
            score: 3.0,
            check: RuleCheck::AttachmentType("exe".to_string()),
        },
    ]
}

fn default_spam_keywords() -> HashSet<String> {
    [
        "viagra", "cialis", "enlargement", "casino", "lottery",
        "winner", "inheritance", "million dollars", "act now",
        "limited time", "free money", "work from home", "make money fast",
        "click here", "unsubscribe", "opt out", "risk free",
        "no obligation", "satisfaction guaranteed", "order now",
    ].iter().map(|s| s.to_string()).collect()
}

fn default_ham_keywords() -> HashSet<String> {
    [
        "meeting", "schedule", "project", "deadline", "report",
        "invoice", "quarterly", "attachment", "regards", "sincerely",
        "follow up", "discussion", "review", "update", "team",
    ].iter().map(|s| s.to_string()).collect()
}
