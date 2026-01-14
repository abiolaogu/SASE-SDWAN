//! Suricata Rule Parser
//!
//! Parses Suricata/Snort rule syntax into structured rule objects
//! that can be compiled into Hyperscan patterns.

use crate::{ActionType, Category, IpsError, Result, Severity};
use std::collections::HashMap;
use std::path::Path;

/// Protocol types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Tls,
    Dns,
    Smtp,
    Ftp,
    Ssh,
    Any,
}

impl Protocol {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            "ip" => Self::Ip,
            "http" => Self::Http,
            "tls" | "ssl" => Self::Tls,
            "dns" => Self::Dns,
            "smtp" => Self::Smtp,
            "ftp" => Self::Ftp,
            "ssh" => Self::Ssh,
            _ => Self::Any,
        }
    }
}

/// Rule action
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Alert,
    Drop,
    Reject,
    Pass,
    Log,
}

impl RuleAction {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "alert" => Some(Self::Alert),
            "drop" => Some(Self::Drop),
            "reject" => Some(Self::Reject),
            "pass" => Some(Self::Pass),
            "log" => Some(Self::Log),
            _ => None,
        }
    }
}

/// Content pattern options
#[derive(Clone, Debug, Default)]
pub struct ContentOptions {
    pub nocase: bool,
    pub depth: Option<u32>,
    pub offset: Option<u32>,
    pub distance: Option<i32>,
    pub within: Option<u32>,
    pub fast_pattern: bool,
    pub negated: bool,
}

/// Content pattern
#[derive(Clone, Debug)]
pub struct ContentPattern {
    pub pattern: String,
    pub is_hex: bool,
    pub options: ContentOptions,
}

/// PCRE pattern
#[derive(Clone, Debug)]
pub struct PcrePattern {
    pub pattern: String,
    pub modifiers: String,
    pub negated: bool,
}

/// HTTP-specific options
#[derive(Clone, Debug, Default)]
pub struct HttpOptions {
    pub http_method: bool,
    pub http_uri: bool,
    pub http_raw_uri: bool,
    pub http_header: bool,
    pub http_raw_header: bool,
    pub http_cookie: bool,
    pub http_user_agent: bool,
    pub http_host: bool,
    pub http_request_body: bool,
    pub http_response_body: bool,
    pub http_stat_code: bool,
    pub http_stat_msg: bool,
}

/// Rule metadata
#[derive(Clone, Debug, Default)]
pub struct RuleMetadata {
    pub msg: String,
    pub sid: u32,
    pub rev: u32,
    pub classtype: Option<String>,
    pub priority: Option<u32>,
    pub severity: Severity,
    pub category: Option<Category>,
    pub reference: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub cve: Vec<String>,
}

/// Parsed Suricata rule
#[derive(Clone, Debug)]
pub struct SuricataRule {
    /// Rule action (alert, drop, etc.)
    pub action: RuleAction,
    
    /// Protocol
    pub protocol: Protocol,
    
    /// Source address
    pub src_addr: String,
    
    /// Source port
    pub src_port: String,
    
    /// Direction (-> or <>)
    pub direction: String,
    
    /// Destination address
    pub dst_addr: String,
    
    /// Destination port
    pub dst_port: String,
    
    /// Content patterns
    pub content_patterns: Vec<ContentPattern>,
    
    /// PCRE patterns
    pub pcre_patterns: Vec<PcrePattern>,
    
    /// HTTP-specific options
    pub http_options: HttpOptions,
    
    /// Metadata
    pub metadata: RuleMetadata,
    
    /// Flow options
    pub flow: Option<String>,
    
    /// Threshold/detection_filter
    pub threshold: Option<String>,
    
    /// Raw rule text
    pub raw: String,
}

impl Default for SuricataRule {
    fn default() -> Self {
        Self {
            action: RuleAction::Alert,
            protocol: Protocol::Any,
            src_addr: "any".to_string(),
            src_port: "any".to_string(),
            direction: "->".to_string(),
            dst_addr: "any".to_string(),
            dst_port: "any".to_string(),
            content_patterns: Vec::new(),
            pcre_patterns: Vec::new(),
            http_options: HttpOptions::default(),
            metadata: RuleMetadata::default(),
            flow: None,
            threshold: None,
            raw: String::new(),
        }
    }
}

/// Suricata rule parser
pub struct RuleParser {
    /// Parsed rules
    rules: Vec<SuricataRule>,
    
    /// Parse errors
    errors: Vec<(usize, String)>,
}

impl RuleParser {
    /// Create new parser
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            errors: Vec::new(),
        }
    }
    
    /// Parse rules from file
    pub fn parse_file(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)?;
        self.parse_content(&content)
    }
    
    /// Parse rules from string
    pub fn parse_content(&mut self, content: &str) -> Result<usize> {
        let mut rule_buffer = String::new();
        let mut line_num = 0;
        let mut start_line = 0;
        
        for line in content.lines() {
            line_num += 1;
            let trimmed = line.trim();
            
            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            
            // Handle line continuation
            if trimmed.ends_with('\\') {
                if rule_buffer.is_empty() {
                    start_line = line_num;
                }
                rule_buffer.push_str(&trimmed[..trimmed.len()-1]);
                continue;
            }
            
            // Complete rule
            let full_rule = if rule_buffer.is_empty() {
                start_line = line_num;
                trimmed.to_string()
            } else {
                rule_buffer.push_str(trimmed);
                std::mem::take(&mut rule_buffer)
            };
            
            // Parse the rule
            match self.parse_single_rule(&full_rule) {
                Ok(rule) => self.rules.push(rule),
                Err(e) => self.errors.push((start_line, e.to_string())),
            }
        }
        
        Ok(self.rules.len())
    }
    
    /// Parse a single rule
    pub fn parse_single_rule(&self, line: &str) -> Result<SuricataRule> {
        let mut rule = SuricataRule::default();
        rule.raw = line.to_string();
        
        // Find the options section (inside parentheses)
        let options_start = line.find('(')
            .ok_or_else(|| IpsError::ParseError("Missing options section".into()))?;
        let options_end = line.rfind(')')
            .ok_or_else(|| IpsError::ParseError("Missing closing parenthesis".into()))?;
        
        // Parse header: action proto src_addr src_port -> dst_addr dst_port
        let header = &line[..options_start].trim();
        let header_parts: Vec<&str> = header.split_whitespace().collect();
        
        if header_parts.len() < 7 {
            return Err(IpsError::ParseError(format!(
                "Invalid header, expected 7 parts, got {}: {}",
                header_parts.len(), header
            )));
        }
        
        rule.action = RuleAction::from_str(header_parts[0])
            .ok_or_else(|| IpsError::ParseError(format!("Unknown action: {}", header_parts[0])))?;
        rule.protocol = Protocol::from_str(header_parts[1]);
        rule.src_addr = header_parts[2].to_string();
        rule.src_port = header_parts[3].to_string();
        rule.direction = header_parts[4].to_string();
        rule.dst_addr = header_parts[5].to_string();
        rule.dst_port = header_parts[6].to_string();
        
        // Parse options
        let options_str = &line[options_start+1..options_end];
        self.parse_options(&mut rule, options_str)?;
        
        Ok(rule)
    }
    
    /// Parse rule options
    fn parse_options(&self, rule: &mut SuricataRule, options: &str) -> Result<()> {
        let mut current_content: Option<ContentPattern> = None;
        
        // Split by semicolon, but handle quoted strings
        let opts = self.split_options(options);
        
        for opt in opts {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }
            
            // Parse key:value or key
            let (key, value) = if let Some(colon_pos) = opt.find(':') {
                let k = opt[..colon_pos].trim();
                let v = opt[colon_pos+1..].trim();
                // Remove surrounding quotes
                let v = v.trim_matches('"');
                (k, Some(v))
            } else {
                (opt, None)
            };
            
            match key {
                "msg" => {
                    if let Some(v) = value {
                        rule.metadata.msg = v.to_string();
                    }
                }
                "sid" => {
                    if let Some(v) = value {
                        rule.metadata.sid = v.parse().unwrap_or(0);
                    }
                }
                "rev" => {
                    if let Some(v) = value {
                        rule.metadata.rev = v.parse().unwrap_or(1);
                    }
                }
                "classtype" => {
                    if let Some(v) = value {
                        rule.metadata.classtype = Some(v.to_string());
                    }
                }
                "priority" => {
                    if let Some(v) = value {
                        rule.metadata.priority = v.parse().ok();
                    }
                }
                "reference" => {
                    if let Some(v) = value {
                        rule.metadata.reference.push(v.to_string());
                    }
                }
                "content" => {
                    // Finalize previous content if any
                    if let Some(c) = current_content.take() {
                        rule.content_patterns.push(c);
                    }
                    
                    if let Some(v) = value {
                        let (pattern, is_hex, negated) = self.parse_content_value(v);
                        current_content = Some(ContentPattern {
                            pattern,
                            is_hex,
                            options: ContentOptions {
                                negated,
                                ..Default::default()
                            },
                        });
                    }
                }
                "nocase" => {
                    if let Some(ref mut c) = current_content {
                        c.options.nocase = true;
                    }
                }
                "depth" => {
                    if let (Some(ref mut c), Some(v)) = (&mut current_content, value) {
                        c.options.depth = v.parse().ok();
                    }
                }
                "offset" => {
                    if let (Some(ref mut c), Some(v)) = (&mut current_content, value) {
                        c.options.offset = v.parse().ok();
                    }
                }
                "distance" => {
                    if let (Some(ref mut c), Some(v)) = (&mut current_content, value) {
                        c.options.distance = v.parse().ok();
                    }
                }
                "within" => {
                    if let (Some(ref mut c), Some(v)) = (&mut current_content, value) {
                        c.options.within = v.parse().ok();
                    }
                }
                "fast_pattern" => {
                    if let Some(ref mut c) = current_content {
                        c.options.fast_pattern = true;
                    }
                }
                "pcre" => {
                    if let Some(v) = value {
                        if let Some(pcre) = self.parse_pcre(v) {
                            rule.pcre_patterns.push(pcre);
                        }
                    }
                }
                "flow" => {
                    if let Some(v) = value {
                        rule.flow = Some(v.to_string());
                    }
                }
                // HTTP options
                "http_method" => rule.http_options.http_method = true,
                "http_uri" => rule.http_options.http_uri = true,
                "http_raw_uri" => rule.http_options.http_raw_uri = true,
                "http_header" => rule.http_options.http_header = true,
                "http_raw_header" => rule.http_options.http_raw_header = true,
                "http_cookie" => rule.http_options.http_cookie = true,
                "http_user_agent" => rule.http_options.http_user_agent = true,
                "http_host" => rule.http_options.http_host = true,
                "http_request_body" | "http_client_body" => {
                    rule.http_options.http_request_body = true;
                }
                "http_response_body" | "http_server_body" | "file_data" => {
                    rule.http_options.http_response_body = true;
                }
                "http_stat_code" => rule.http_options.http_stat_code = true,
                "http_stat_msg" => rule.http_options.http_stat_msg = true,
                _ => {
                    // Store unknown options in metadata
                    if let Some(v) = value {
                        rule.metadata.metadata.insert(key.to_string(), v.to_string());
                    }
                }
            }
        }
        
        // Finalize last content
        if let Some(c) = current_content {
            rule.content_patterns.push(c);
        }
        
        Ok(())
    }
    
    /// Split options respecting quotes
    fn split_options(&self, options: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut escape_next = false;
        
        for ch in options.chars() {
            if escape_next {
                current.push(ch);
                escape_next = false;
                continue;
            }
            
            match ch {
                '\\' => {
                    escape_next = true;
                    current.push(ch);
                }
                '"' => {
                    in_quotes = !in_quotes;
                    current.push(ch);
                }
                ';' if !in_quotes => {
                    if !current.trim().is_empty() {
                        parts.push(current.trim().to_string());
                    }
                    current.clear();
                }
                _ => current.push(ch),
            }
        }
        
        if !current.trim().is_empty() {
            parts.push(current.trim().to_string());
        }
        
        parts
    }
    
    /// Parse content value
    fn parse_content_value(&self, value: &str) -> (String, bool, bool) {
        let mut s = value;
        let mut negated = false;
        
        // Check for negation
        if s.starts_with('!') {
            negated = true;
            s = &s[1..];
        }
        
        // Remove quotes
        s = s.trim_matches('"');
        
        // Check for hex encoding |xx xx|
        if s.starts_with('|') && s.ends_with('|') {
            let hex = &s[1..s.len()-1];
            let pattern = self.hex_to_pattern(hex);
            return (pattern, true, negated);
        }
        
        // Unescape string
        let pattern = self.unescape_content(s);
        (pattern, false, negated)
    }
    
    /// Convert hex pattern to string
    fn hex_to_pattern(&self, hex: &str) -> String {
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        
        // Convert to escaped regex pattern
        bytes.iter()
            .map(|b| format!("\\x{:02x}", b))
            .collect()
    }
    
    /// Unescape content patterns
    fn unescape_content(&self, s: &str) -> String {
        s.replace("\\;", ";")
         .replace("\\:", ":")
         .replace("\\\"", "\"")
         .replace("\\\\", "\\")
    }
    
    /// Parse PCRE pattern
    fn parse_pcre(&self, value: &str) -> Option<PcrePattern> {
        let s = value.trim_matches('"');
        
        // Check for negation
        let (s, negated) = if s.starts_with('!') {
            (&s[1..], true)
        } else {
            (s, false)
        };
        
        // PCRE format: /pattern/modifiers
        if !s.starts_with('/') {
            return None;
        }
        
        // Find the last /
        let last_slash = s.rfind('/')?;
        if last_slash == 0 {
            return None;
        }
        
        let pattern = s[1..last_slash].to_string();
        let modifiers = s[last_slash+1..].to_string();
        
        Some(PcrePattern {
            pattern,
            modifiers,
            negated,
        })
    }
    
    /// Get parsed rules
    pub fn rules(&self) -> &[SuricataRule] {
        &self.rules
    }
    
    /// Get parse errors
    pub fn errors(&self) -> &[(usize, String)] {
        &self.errors
    }
    
    /// Take parsed rules
    pub fn into_rules(self) -> Vec<SuricataRule> {
        self.rules
    }
}

impl Default for RuleParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let parser = RuleParser::new();
        
        let rule_str = r#"alert http any any -> any any (msg:"Test Rule"; content:"malware"; nocase; sid:1000001; rev:1;)"#;
        
        let rule = parser.parse_single_rule(rule_str).unwrap();
        
        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Http);
        assert_eq!(rule.metadata.msg, "Test Rule");
        assert_eq!(rule.metadata.sid, 1000001);
        assert_eq!(rule.content_patterns.len(), 1);
        assert_eq!(rule.content_patterns[0].pattern, "malware");
        assert!(rule.content_patterns[0].options.nocase);
    }

    #[test]
    fn test_parse_pcre_rule() {
        let parser = RuleParser::new();
        
        let rule_str = r#"alert http any any -> any any (msg:"PCRE Test"; pcre:"/eval\s*\(/i"; sid:1000002;)"#;
        
        let rule = parser.parse_single_rule(rule_str).unwrap();
        
        assert_eq!(rule.pcre_patterns.len(), 1);
        assert_eq!(rule.pcre_patterns[0].pattern, r"eval\s*\(");
        assert_eq!(rule.pcre_patterns[0].modifiers, "i");
    }

    #[test]
    fn test_parse_hex_content() {
        let parser = RuleParser::new();
        
        let rule_str = r#"alert tcp any any -> any any (msg:"Hex Test"; content:"|00 01 02 03|"; sid:1000003;)"#;
        
        let rule = parser.parse_single_rule(rule_str).unwrap();
        
        assert_eq!(rule.content_patterns.len(), 1);
        assert!(rule.content_patterns[0].is_hex);
    }
}
