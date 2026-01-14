//! CEF (Common Event Format) Formatter
//!
//! Formats security alerts in CEF format for SIEM integration.

use super::pipeline::{SecurityAlert, AlertPriority};

/// CEF formatter
pub struct CefFormatter {
    /// Device vendor
    vendor: String,
    
    /// Device product
    product: String,
    
    /// Device version
    version: String,
}

impl CefFormatter {
    /// Create new formatter
    pub fn new() -> Self {
        Self {
            vendor: "OpenSASE".into(),
            product: "OISE".into(),
            version: "1.0".into(),
        }
    }
    
    /// Format alert to CEF
    pub fn format(&self, alert: &SecurityAlert) -> String {
        // CEF format:
        // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        
        let severity = match alert.priority {
            AlertPriority::Low => 3,
            AlertPriority::Medium => 5,
            AlertPriority::High => 8,
            AlertPriority::Critical => 10,
        };
        
        let mut extensions = Vec::new();
        
        // Add source
        if let Some(ref ip) = alert.src_ip {
            extensions.push(format!("src={}", ip));
        }
        if let Some(port) = alert.src_port {
            extensions.push(format!("spt={}", port));
        }
        
        // Add destination
        if let Some(ref ip) = alert.dst_ip {
            extensions.push(format!("dst={}", ip));
        }
        if let Some(port) = alert.dst_port {
            extensions.push(format!("dpt={}", port));
        }
        
        // Add protocol
        extensions.push(format!("proto={}", alert.protocol));
        
        // Add category
        extensions.push(format!("cat={}", alert.category));
        
        // Add action
        extensions.push(format!("act={}", alert.action));
        
        // Add tenant
        if let Some(tenant) = alert.tenant_id {
            extensions.push(format!("cs1={}", tenant));
            extensions.push("cs1Label=TenantID".into());
        }
        
        // Add timestamp
        extensions.push(format!("rt={}", alert.timestamp.timestamp_millis()));
        
        // Escape message
        let msg = Self::escape_cef(&alert.msg);
        
        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            self.vendor,
            self.product,
            self.version,
            alert.sid,
            msg,
            severity,
            extensions.join(" ")
        )
    }
    
    /// Escape CEF special characters
    fn escape_cef(s: &str) -> String {
        s.replace('\\', "\\\\")
         .replace('|', "\\|")
         .replace('\n', "\\n")
         .replace('\r', "\\r")
         .replace('=', "\\=")
    }
}

impl Default for CefFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cef_format() {
        let formatter = CefFormatter::new();
        
        let alert = SecurityAlert::new(1000001, "SQL Injection", AlertPriority::High)
            .with_source("192.168.1.1", 12345)
            .with_destination("10.0.0.1", 80)
            .with_category("web-attack");
        
        let cef = formatter.format(&alert);
        
        assert!(cef.starts_with("CEF:0|OpenSASE|OISE|1.0|"));
        assert!(cef.contains("src=192.168.1.1"));
        assert!(cef.contains("dst=10.0.0.1"));
        assert!(cef.contains("cat=web-attack"));
    }

    #[test]
    fn test_cef_escape() {
        let escaped = CefFormatter::escape_cef("test|pipe\\backslash");
        assert_eq!(escaped, "test\\|pipe\\\\backslash");
    }
}
