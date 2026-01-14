//! Email MIME Parser
//!
//! Parse and analyze email MIME structure.

use crate::{EmailMessage, EmailHeaders, EmailBody, ContentType, Attachment, NestedFile, ExtractedUrl, UrlContext};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

/// Email parser for MIME messages
pub struct EmailParser {
    /// Maximum recursion depth for MIME parts
    max_depth: usize,
    /// Maximum attachment size to process
    max_attachment_size: usize,
}

impl EmailParser {
    pub fn new() -> Self {
        Self {
            max_depth: 10,
            max_attachment_size: 100 * 1024 * 1024, // 100MB
        }
    }
    
    /// Parse raw email bytes into EmailMessage
    pub fn parse(&self, raw: &[u8], envelope: crate::EmailEnvelope) -> Result<EmailMessage, ParseError> {
        let message_id = uuid::Uuid::new_v4().to_string();
        
        // Parse headers
        let headers = self.parse_headers(raw)?;
        
        // Parse body and attachments
        let (body, attachments) = self.parse_body(raw)?;
        
        Ok(EmailMessage {
            id: message_id,
            envelope,
            headers,
            body,
            attachments,
            received_at: chrono::Utc::now(),
            size_bytes: raw.len(),
        })
    }
    
    fn parse_headers(&self, raw: &[u8]) -> Result<EmailHeaders, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut headers = EmailHeaders::default();
        let mut in_headers = true;
        
        for line in text.lines() {
            if line.is_empty() {
                in_headers = false;
                continue;
            }
            
            if !in_headers {
                break;
            }
            
            if let Some((name, value)) = line.split_once(':') {
                let name_lower = name.trim().to_lowercase();
                let value = value.trim().to_string();
                
                match name_lower.as_str() {
                    "from" => headers.from = value,
                    "to" => headers.to = parse_address_list(&value),
                    "cc" => headers.cc = parse_address_list(&value),
                    "subject" => headers.subject = value,
                    "date" => headers.date = Some(value),
                    "message-id" => headers.message_id = Some(value),
                    "reply-to" => headers.reply_to = Some(value),
                    "return-path" => headers.return_path = Some(value),
                    "received" => headers.received.push(value),
                    "dkim-signature" => headers.dkim_signature = Some(value),
                    "authentication-results" => headers.authentication_results = Some(value),
                    _ if name_lower.starts_with("x-") => {
                        headers.x_headers.insert(name.to_string(), value);
                    }
                    _ => {}
                }
            }
        }
        
        Ok(headers)
    }
    
    fn parse_body(&self, raw: &[u8]) -> Result<(EmailBody, Vec<Attachment>), ParseError> {
        let text = String::from_utf8_lossy(raw);
        let mut body = EmailBody {
            content_type: ContentType::TextPlain,
            text_plain: None,
            text_html: None,
            urls: Vec::new(),
        };
        let mut attachments = Vec::new();
        
        // Find body start (after empty line)
        let body_start = text.find("\r\n\r\n")
            .or_else(|| text.find("\n\n"))
            .unwrap_or(0);
        
        let body_text = &text[body_start..];
        
        // Extract plain text
        body.text_plain = Some(body_text.to_string());
        
        // Extract URLs
        body.urls = self.extract_urls(body_text);
        
        // Check for HTML
        if body_text.contains("<html") || body_text.contains("<HTML") {
            body.content_type = ContentType::TextHtml;
            body.text_html = Some(body_text.to_string());
        }
        
        // Extract attachments (simplified - would use mail-parser in production)
        // TODO: Full MIME multipart parsing
        
        Ok((body, attachments))
    }
    
    fn extract_urls(&self, text: &str) -> Vec<ExtractedUrl> {
        let url_regex = regex::Regex::new(
            r"https?://[^\s<>\[\]{}|\\^`\x00-\x1f\x7f]+"
        ).unwrap();
        
        let mut urls = Vec::new();
        
        for cap in url_regex.find_iter(text) {
            let url_str = cap.as_str().to_string();
            let is_shortened = is_url_shortener(&url_str);
            
            urls.push(ExtractedUrl {
                url: url_str,
                display_text: None,
                context: UrlContext::Body,
                is_shortened,
                final_url: None,
            });
        }
        
        urls
    }
}

impl Default for EmailParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse comma-separated address list
fn parse_address_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|addr| addr.trim().to_string())
        .filter(|addr| !addr.is_empty())
        .collect()
}

/// Check if URL is from a known shortener
fn is_url_shortener(url: &str) -> bool {
    let shorteners = [
        "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly",
        "is.gd", "buff.ly", "j.mp", "t.ly", "rb.gy",
    ];
    
    for shortener in shorteners {
        if url.contains(shortener) {
            return true;
        }
    }
    false
}

/// Calculate SHA256 hash
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid MIME structure: {0}")]
    InvalidMime(String),
    #[error("Encoding error: {0}")]
    Encoding(String),
    #[error("Recursion limit exceeded")]
    RecursionLimit,
}

/// Header analysis for security
pub struct HeaderAnalyzer;

impl HeaderAnalyzer {
    /// Check for header anomalies
    pub fn analyze(headers: &EmailHeaders) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis::default();
        
        // Check From/Reply-To mismatch
        if let Some(reply_to) = &headers.reply_to {
            if !headers.from.is_empty() && !reply_to.contains(&extract_domain(&headers.from)) {
                analysis.from_reply_to_mismatch = true;
                analysis.score += 2.0;
            }
        }
        
        // Check for suspicious X-headers
        for (name, value) in &headers.x_headers {
            if name.to_lowercase().contains("mailer") {
                analysis.x_mailer = Some(value.clone());
                
                // Known spam mailers
                let spam_mailers = ["PHPMailer", "The Bat!", "YZSOFT"];
                for mailer in spam_mailers {
                    if value.contains(mailer) {
                        analysis.score += 1.5;
                    }
                }
            }
        }
        
        // Check for unusual Received chain
        if headers.received.len() > 10 {
            analysis.excessive_received_headers = true;
            analysis.score += 1.0;
        }
        
        // Check for missing Message-ID
        if headers.message_id.is_none() {
            analysis.missing_message_id = true;
            analysis.score += 0.5;
        }
        
        analysis
    }
}

fn extract_domain(email: &str) -> String {
    email.split('@')
        .nth(1)
        .unwrap_or("")
        .split('>')
        .next()
        .unwrap_or("")
        .to_string()
}

#[derive(Debug, Clone, Default)]
pub struct HeaderAnalysis {
    pub from_reply_to_mismatch: bool,
    pub x_mailer: Option<String>,
    pub excessive_received_headers: bool,
    pub missing_message_id: bool,
    pub score: f64,
}
