//! Business Email Compromise (BEC) Detection
//!
//! ML/NLP-based detection of executive fraud and impersonation attacks.

use crate::{EmailMessage, VerdictReason, ThreatCategory};
use std::collections::{HashMap, HashSet};

/// BEC detector using NLP and behavioral analysis
pub struct BecDetector {
    /// Known executives/VIPs
    vip_list: HashMap<String, VipInfo>,
    /// Trained model (placeholder)
    model: BecModel,
    /// Financial keywords
    financial_keywords: HashSet<String>,
    /// Urgency phrases
    urgency_phrases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VipInfo {
    pub name: String,
    pub email: String,
    pub title: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BecResult {
    pub score: f64,
    pub is_bec: bool,
    pub bec_type: Option<BecType>,
    pub reasons: Vec<VerdictReason>,
    pub impersonated_person: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BecType {
    /// CEO/executive impersonation
    CeoFraud,
    /// Vendor impersonation
    VendorFraud,
    /// Employee impersonation
    EmployeeFraud,
    /// Invoice scam
    InvoiceFraud,
    /// Gift card scam
    GiftCardScam,
    /// Wire transfer request
    WireTransfer,
    /// Payroll diversion
    PayrollDiversion,
}

struct BecModel {
    // In production: trained NLP model
}

impl BecDetector {
    pub fn new() -> Self {
        Self {
            vip_list: HashMap::new(),
            model: BecModel {},
            financial_keywords: financial_keywords(),
            urgency_phrases: urgency_phrases(),
        }
    }
    
    /// Detect BEC indicators in email
    pub async fn detect(&self, message: &EmailMessage) -> BecResult {
        let mut result = BecResult {
            score: 0.0,
            is_bec: false,
            bec_type: None,
            reasons: Vec::new(),
            impersonated_person: None,
        };
        
        // 1. Check for VIP impersonation
        let impersonation = self.check_vip_impersonation(message);
        result.score += impersonation.score;
        if impersonation.impersonated.is_some() {
            result.reasons.extend(impersonation.reasons);
            result.impersonated_person = impersonation.impersonated;
        }
        
        // 2. Check for financial keywords + urgency
        let financial = self.check_financial_urgency(message);
        result.score += financial.score;
        result.reasons.extend(financial.reasons);
        
        // 3. Check for wire transfer/gift card patterns
        let scam_type = self.detect_scam_type(message);
        if let Some((bec_type, score, reasons)) = scam_type {
            result.score += score;
            result.bec_type = Some(bec_type);
            result.reasons.extend(reasons);
        }
        
        // 4. Check sender anomalies
        let anomaly = self.check_sender_anomalies(message);
        result.score += anomaly.score;
        result.reasons.extend(anomaly.reasons);
        
        // 5. NLP sentiment analysis for pressure tactics
        let nlp_score = self.nlp_analysis(message);
        result.score += nlp_score;
        
        // Threshold
        result.is_bec = result.score >= 6.0;
        
        result
    }
    
    fn check_vip_impersonation(&self, message: &EmailMessage) -> ImpersonationCheck {
        let mut check = ImpersonationCheck::default();
        
        let from = &message.headers.from.to_lowercase();
        let reply_to = message.headers.reply_to.as_ref()
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        
        for (_, vip) in &self.vip_list {
            let vip_email = vip.email.to_lowercase();
            let vip_name = vip.name.to_lowercase();
            
            // Display name contains VIP name but email is different
            if from.contains(&vip_name) && !from.contains(&vip_email) {
                check.score += 5.0;
                check.impersonated = Some(vip.name.clone());
                check.reasons.push(VerdictReason {
                    category: ThreatCategory::Bec,
                    description: format!(
                        "Display name impersonates {} but uses different email",
                        vip.name
                    ),
                    confidence: 0.9,
                    source: "vip_impersonation".to_string(),
                });
            }
            
            // Reply-to is different from sender
            if !reply_to.is_empty() && from.contains(&vip_name) && !reply_to.contains(&vip_email) {
                check.score += 3.0;
                check.reasons.push(VerdictReason {
                    category: ThreatCategory::Bec,
                    description: "Reply-to redirects away from claimed sender".to_string(),
                    confidence: 0.8,
                    source: "reply_to_mismatch".to_string(),
                });
            }
            
            // Check aliases
            for alias in &vip.aliases {
                if from.contains(&alias.to_lowercase()) && !from.contains(&vip_email) {
                    check.score += 4.0;
                    check.impersonated = Some(vip.name.clone());
                }
            }
        }
        
        check
    }
    
    fn check_financial_urgency(&self, message: &EmailMessage) -> FinancialCheck {
        let mut check = FinancialCheck::default();
        
        let body = message.body.text_plain.as_deref().unwrap_or("")
            .to_lowercase();
        let subject = message.headers.subject.to_lowercase();
        let combined = format!("{} {}", subject, body);
        
        let mut financial_count = 0;
        for keyword in &self.financial_keywords {
            if combined.contains(keyword) {
                financial_count += 1;
            }
        }
        
        let mut urgency_count = 0;
        for phrase in &self.urgency_phrases {
            if combined.contains(&phrase.to_lowercase()) {
                urgency_count += 1;
            }
        }
        
        // High financial + urgency = suspicious
        if financial_count >= 2 && urgency_count >= 1 {
            check.score += 3.0;
            check.reasons.push(VerdictReason {
                category: ThreatCategory::Bec,
                description: format!(
                    "Contains {} financial terms and {} urgency phrases",
                    financial_count, urgency_count
                ),
                confidence: 0.7,
                source: "financial_urgency".to_string(),
            });
        }
        
        check
    }
    
    fn detect_scam_type(&self, message: &EmailMessage) -> Option<(BecType, f64, Vec<VerdictReason>)> {
        let body = message.body.text_plain.as_deref().unwrap_or("")
            .to_lowercase();
        
        // Gift card scam
        if body.contains("gift card") || body.contains("giftcard") {
            if body.contains("buy") || body.contains("purchase") || body.contains("get") {
                return Some((
                    BecType::GiftCardScam,
                    5.0,
                    vec![VerdictReason {
                        category: ThreatCategory::Bec,
                        description: "Gift card purchase request detected".to_string(),
                        confidence: 0.85,
                        source: "gift_card_scam".to_string(),
                    }]
                ));
            }
        }
        
        // Wire transfer
        if body.contains("wire transfer") || body.contains("wire the funds") 
            || body.contains("bank transfer") 
        {
            return Some((
                BecType::WireTransfer,
                5.0,
                vec![VerdictReason {
                    category: ThreatCategory::Bec,
                    description: "Wire transfer request detected".to_string(),
                    confidence: 0.8,
                    source: "wire_transfer".to_string(),
                }]
            ));
        }
        
        // Invoice fraud
        if body.contains("update") && body.contains("bank") && body.contains("details") {
            return Some((
                BecType::InvoiceFraud,
                4.0,
                vec![VerdictReason {
                    category: ThreatCategory::Bec,
                    description: "Bank details update request detected".to_string(),
                    confidence: 0.75,
                    source: "invoice_fraud".to_string(),
                }]
            ));
        }
        
        // Payroll diversion
        if body.contains("direct deposit") || 
           (body.contains("payroll") && body.contains("account")) 
        {
            return Some((
                BecType::PayrollDiversion,
                4.0,
                vec![VerdictReason {
                    category: ThreatCategory::Bec,
                    description: "Payroll update request detected".to_string(),
                    confidence: 0.75,
                    source: "payroll_diversion".to_string(),
                }]
            ));
        }
        
        None
    }
    
    fn check_sender_anomalies(&self, message: &EmailMessage) -> AnomalyCheck {
        let mut check = AnomalyCheck::default();
        
        let from_domain = extract_domain(&message.headers.from);
        
        // Free email provider claiming to be executive
        let free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"];
        if free_providers.contains(&from_domain.as_str()) {
            let subject = message.headers.subject.to_lowercase();
            if subject.contains("urgent") || subject.contains("confidential") 
                || subject.contains("request") 
            {
                check.score += 2.0;
                check.reasons.push(VerdictReason {
                    category: ThreatCategory::Bec,
                    description: "Urgent business request from free email provider".to_string(),
                    confidence: 0.6,
                    source: "free_email_anomaly".to_string(),
                });
            }
        }
        
        // Recently registered lookalike domain detection would go here
        
        check
    }
    
    fn nlp_analysis(&self, message: &EmailMessage) -> f64 {
        let body = message.body.text_plain.as_deref().unwrap_or("");
        
        let mut score = 0.0;
        
        // Pressure/urgency patterns
        let pressure_patterns = [
            "keep this between us",
            "don't tell anyone",
            "this is confidential",
            "i need this done today",
            "can you handle this right now",
            "are you available",
            "i need a favor",
            "can you help me with something",
        ];
        
        let body_lower = body.to_lowercase();
        for pattern in pressure_patterns {
            if body_lower.contains(pattern) {
                score += 1.0;
            }
        }
        
        score.min(3.0)
    }
    
    /// Add VIP to protection list
    pub fn add_vip(&mut self, email: &str, name: &str, title: &str, aliases: Vec<String>) {
        self.vip_list.insert(email.to_lowercase(), VipInfo {
            name: name.to_string(),
            email: email.to_string(),
            title: title.to_string(),
            aliases,
        });
    }
}

impl Default for BecDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct ImpersonationCheck {
    score: f64,
    impersonated: Option<String>,
    reasons: Vec<VerdictReason>,
}

#[derive(Debug, Default)]
struct FinancialCheck {
    score: f64,
    reasons: Vec<VerdictReason>,
}

#[derive(Debug, Default)]
struct AnomalyCheck {
    score: f64,
    reasons: Vec<VerdictReason>,
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

fn financial_keywords() -> HashSet<String> {
    [
        "wire", "transfer", "payment", "invoice", "bank", "account",
        "routing", "swift", "iban", "funds", "money", "dollars",
        "urgent payment", "overdue", "past due", "pay now",
    ].iter().map(|s| s.to_string()).collect()
}

fn urgency_phrases() -> Vec<String> {
    vec![
        "urgent".to_string(),
        "asap".to_string(),
        "immediately".to_string(),
        "right away".to_string(),
        "as soon as possible".to_string(),
        "time sensitive".to_string(),
        "today".to_string(),
        "before end of day".to_string(),
        "cannot wait".to_string(),
    ]
}
