//! HTTP Protocol Analyzer
//!
//! Analyzes HTTP requests and responses for security threats
//! including SQL injection, XSS, path traversal, and more.

use std::collections::HashMap;

/// HTTP analysis verdict
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpVerdict {
    /// Allow request
    Allow,
    
    /// Block request
    Block(&'static str),
    
    /// Alert but allow
    Alert(&'static str),
    
    /// Need more data
    NeedMore,
}

/// Parsed HTTP request info
#[derive(Clone, Debug, Default)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub headers: HashMap<String, String>,
    pub body_offset: usize,
}

/// HTTP analyzer configuration
#[derive(Clone, Debug)]
pub struct HttpConfig {
    /// Block SQL injection attempts
    pub detect_sqli: bool,
    
    /// Block XSS attempts
    pub detect_xss: bool,
    
    /// Block path traversal
    pub detect_path_traversal: bool,
    
    /// Block command injection
    pub detect_command_injection: bool,
    
    /// Allowed HTTP methods
    pub allowed_methods: Vec<String>,
    
    /// Max URL length
    pub max_url_length: usize,
    
    /// Max header size
    pub max_header_size: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            detect_sqli: true,
            detect_xss: true,
            detect_path_traversal: true,
            detect_command_injection: true,
            allowed_methods: vec![
                "GET".into(), "POST".into(), "PUT".into(), 
                "DELETE".into(), "HEAD".into(), "OPTIONS".into(),
            ],
            max_url_length: 8192,
            max_header_size: 32768,
        }
    }
}

/// HTTP protocol analyzer
pub struct HttpAnalyzer {
    config: HttpConfig,
}

impl HttpAnalyzer {
    /// Create new analyzer
    pub fn new(config: HttpConfig) -> Self {
        Self { config }
    }
    
    /// Analyze HTTP request
    pub fn analyze_request(&self, data: &[u8]) -> HttpVerdict {
        // Parse request
        let request = match self.parse_request(data) {
            Some(r) => r,
            None => return HttpVerdict::NeedMore,
        };
        
        // Check URL length
        if request.path.len() > self.config.max_url_length {
            return HttpVerdict::Block("URL too long");
        }
        
        // Check method
        if !self.config.allowed_methods.contains(&request.method) {
            return HttpVerdict::Block("HTTP method not allowed");
        }
        
        // SQL injection detection
        if self.config.detect_sqli && self.detect_sqli(&request.path) {
            return HttpVerdict::Block("SQL injection detected");
        }
        
        // XSS detection
        if self.config.detect_xss && self.detect_xss(&request.path) {
            return HttpVerdict::Block("XSS attempt detected");
        }
        
        // Path traversal detection
        if self.config.detect_path_traversal && self.detect_path_traversal(&request.path) {
            return HttpVerdict::Block("Path traversal detected");
        }
        
        // Command injection detection
        if self.config.detect_command_injection {
            if self.detect_command_injection(&request.path) {
                return HttpVerdict::Block("Command injection detected");
            }
        }
        
        // Check body for vulnerabilities (if POST/PUT)
        if (request.method == "POST" || request.method == "PUT") 
            && request.body_offset < data.len() 
        {
            let body = &data[request.body_offset..];
            if let Some(body_str) = std::str::from_utf8(body).ok() {
                if self.config.detect_sqli && self.detect_sqli(body_str) {
                    return HttpVerdict::Block("SQL injection in body");
                }
                if self.config.detect_xss && self.detect_xss(body_str) {
                    return HttpVerdict::Block("XSS in body");
                }
            }
        }
        
        HttpVerdict::Allow
    }
    
    /// Parse HTTP request
    fn parse_request(&self, data: &[u8]) -> Option<HttpRequest> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        
        match req.parse(data) {
            Ok(httparse::Status::Complete(body_offset)) => {
                let mut request = HttpRequest {
                    method: req.method?.to_string(),
                    path: req.path?.to_string(),
                    version: format!("{}", req.version?),
                    body_offset,
                    ..Default::default()
                };
                
                for header in req.headers.iter() {
                    let name = header.name.to_lowercase();
                    let value = String::from_utf8_lossy(header.value).to_string();
                    
                    match name.as_str() {
                        "host" => request.host = Some(value.clone()),
                        "user-agent" => request.user_agent = Some(value.clone()),
                        "content-type" => request.content_type = Some(value.clone()),
                        "content-length" => {
                            request.content_length = value.parse().ok();
                        }
                        _ => {}
                    }
                    
                    request.headers.insert(name, value);
                }
                
                Some(request)
            }
            Ok(httparse::Status::Partial) => None,
            Err(_) => None,
        }
    }
    
    /// Detect SQL injection patterns
    fn detect_sqli(&self, input: &str) -> bool {
        let input_lower = input.to_lowercase();
        
        // SQL keywords combined with operators
        let patterns = [
            "' or '", "' or 1", "1=1", "1 = 1",
            "union select", "union all select",
            "' and '", "' and 1",
            "drop table", "drop database",
            "insert into", "delete from",
            "update set", "select from",
            "exec(", "execute(",
            "xp_cmdshell", "sp_executesql",
            "waitfor delay", "benchmark(",
            "sleep(", "pg_sleep(",
            "'; --", "';--", "' --",
            "/**/", "/***/",
            "char(", "concat(",
            "0x", "cast(",
            "convert(", "substr(",
            "ascii(", "ord(",
        ];
        
        for pattern in patterns {
            if input_lower.contains(pattern) {
                return true;
            }
        }
        
        // Check for SQL comment sequences
        if input.contains("--") && (
            input_lower.contains("select") ||
            input_lower.contains("union") ||
            input_lower.contains("insert") ||
            input_lower.contains("update") ||
            input_lower.contains("delete")
        ) {
            return true;
        }
        
        false
    }
    
    /// Detect XSS patterns
    fn detect_xss(&self, input: &str) -> bool {
        let input_lower = input.to_lowercase();
        
        let patterns = [
            "<script", "</script>",
            "javascript:", "vbscript:",
            "onerror=", "onload=",
            "onclick=", "onmouseover=",
            "onfocus=", "onblur=",
            "eval(", "expression(",
            "document.cookie", "document.location",
            "window.location", "location.href",
            "<iframe", "<object",
            "<embed", "<form",
            "<img src=", "<svg",
            "alert(", "prompt(",
            "confirm(", "String.fromCharCode",
            "&#x", "&#", // HTML entities
            "\\x", "\\u00", // Hex encoding
        ];
        
        for pattern in patterns {
            if input_lower.contains(pattern) {
                return true;
            }
        }
        
        // Check for encoded scripts
        if input.contains("%3C") && input.contains("%3E") {
            return true; // URL encoded < >
        }
        
        false
    }
    
    /// Detect path traversal
    fn detect_path_traversal(&self, path: &str) -> bool {
        let patterns = [
            "../", "..\\",
            "%2e%2e%2f", "%2e%2e/",
            "..%2f", "%2e%2e\\",
            "..%5c", "%2e%2e%5c",
            "....//", "....\\\\",
            "/etc/passwd", "/etc/shadow",
            "c:\\windows", "c:/windows",
            "/proc/self", "/var/log",
        ];
        
        let path_lower = path.to_lowercase();
        
        for pattern in patterns {
            if path_lower.contains(pattern) {
                return true;
            }
        }
        
        false
    }
    
    /// Detect command injection
    fn detect_command_injection(&self, input: &str) -> bool {
        let patterns = [
            ";", "|", "&", "`",
            "$(", "${", 
            "\n", "\r",
            ">/", ">>",
            "&&", "||",
            "ping ", "wget ",
            "curl ", "nc ",
            "netcat ", "bash ",
            "/bin/sh", "/bin/bash",
            "cmd.exe", "powershell",
            "nslookup", "dig ",
        ];
        
        for pattern in patterns {
            if input.contains(pattern) {
                // Check for shell metacharacters in dangerous contexts
                if pattern.len() == 1 {
                    // Single char patterns need context
                    let dangerous_cmds = ["ls", "cat", "rm", "mv", "cp", "wget", "curl"];
                    for cmd in dangerous_cmds {
                        if input.to_lowercase().contains(cmd) {
                            return true;
                        }
                    }
                } else {
                    return true;
                }
            }
        }
        
        false
    }
}

impl Default for HttpAnalyzer {
    fn default() -> Self {
        Self::new(HttpConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_detection() {
        let analyzer = HttpAnalyzer::default();
        
        assert!(analyzer.detect_sqli("id=1' OR '1'='1"));
        assert!(analyzer.detect_sqli("id=1 UNION SELECT * FROM users"));
        assert!(analyzer.detect_sqli("'; DROP TABLE users; --"));
        
        assert!(!analyzer.detect_sqli("/products/123"));
        assert!(!analyzer.detect_sqli("search=hello world"));
    }

    #[test]
    fn test_xss_detection() {
        let analyzer = HttpAnalyzer::default();
        
        assert!(analyzer.detect_xss("<script>alert('xss')</script>"));
        assert!(analyzer.detect_xss("javascript:alert(1)"));
        assert!(analyzer.detect_xss("<img src=x onerror=alert(1)>"));
        
        assert!(!analyzer.detect_xss("Hello World"));
        assert!(!analyzer.detect_xss("/search?q=test"));
    }

    #[test]
    fn test_path_traversal() {
        let analyzer = HttpAnalyzer::default();
        
        assert!(analyzer.detect_path_traversal("../../etc/passwd"));
        assert!(analyzer.detect_path_traversal("/var/log/../../../etc/shadow"));
        
        assert!(!analyzer.detect_path_traversal("/images/logo.png"));
    }
}
