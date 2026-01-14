//! Event Normalization
//!
//! Convert raw logs to Common Event Format (CEF).

use crate::{SecurityEvent, EventType, Severity, EventSource, Indicator, IndicatorType};
use std::collections::HashMap;

pub struct EventNormalizer {
    parsers: dashmap::DashMap<String, Box<dyn EventParser>>,
    stats: NormalizerStats,
}

struct NormalizerStats {
    events_processed: std::sync::atomic::AtomicU64,
    events_failed: std::sync::atomic::AtomicU64,
}

#[async_trait::async_trait]
pub trait EventParser: Send + Sync {
    fn source_type(&self) -> &str;
    fn parse(&self, raw: &str) -> Result<SecurityEvent, ParseError>;
}

/// Common Event Format (CEF) event
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CefEvent {
    pub version: u8,
    pub device_vendor: String,
    pub device_product: String,
    pub device_version: String,
    pub signature_id: String,
    pub name: String,
    pub severity: u8,
    pub extensions: HashMap<String, String>,
}

impl EventNormalizer {
    pub fn new() -> Self {
        let normalizer = Self {
            parsers: dashmap::DashMap::new(),
            stats: NormalizerStats {
                events_processed: std::sync::atomic::AtomicU64::new(0),
                events_failed: std::sync::atomic::AtomicU64::new(0),
            },
        };
        normalizer.register_default_parsers();
        normalizer
    }
    
    fn register_default_parsers(&self) {
        self.parsers.insert("syslog".to_string(), Box::new(SyslogParser));
        self.parsers.insert("json".to_string(), Box::new(JsonParser));
        self.parsers.insert("cef".to_string(), Box::new(CefParser));
        self.parsers.insert("leef".to_string(), Box::new(LeefParser));
    }
    
    pub fn normalize(&self, source_type: &str, raw: &str) -> Result<SecurityEvent, ParseError> {
        let parser = self.parsers.get(source_type)
            .ok_or(ParseError::UnknownSource(source_type.to_string()))?;
        
        match parser.parse(raw) {
            Ok(event) => {
                self.stats.events_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(event)
            }
            Err(e) => {
                self.stats.events_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(e)
            }
        }
    }
    
    pub fn to_cef(&self, event: &SecurityEvent) -> CefEvent {
        let mut extensions = HashMap::new();
        extensions.insert("src".to_string(), event.source.ip.clone().unwrap_or_default());
        extensions.insert("shost".to_string(), event.source.host.clone().unwrap_or_default());
        extensions.insert("rt".to_string(), event.timestamp.timestamp_millis().to_string());
        extensions.insert("msg".to_string(), event.description.clone());
        
        for (i, indicator) in event.indicators.iter().enumerate() {
            extensions.insert(format!("cs{}Label", i+1), format!("{:?}", indicator.indicator_type));
            extensions.insert(format!("cs{}", i+1), indicator.value.clone());
        }
        
        CefEvent {
            version: 0,
            device_vendor: "OpenSASE".to_string(),
            device_product: event.source.component.clone(),
            device_version: "1.0".to_string(),
            signature_id: format!("{:?}", event.event_type),
            name: event.description.clone(),
            severity: match event.severity {
                Severity::Info => 1,
                Severity::Low => 3,
                Severity::Medium => 5,
                Severity::High => 8,
                Severity::Critical => 10,
            },
            extensions,
        }
    }
    
    pub fn register_parser(&self, parser: Box<dyn EventParser>) {
        self.parsers.insert(parser.source_type().to_string(), parser);
    }
}

impl Default for EventNormalizer {
    fn default() -> Self { Self::new() }
}

// Syslog Parser
struct SyslogParser;

#[async_trait::async_trait]
impl EventParser for SyslogParser {
    fn source_type(&self) -> &str { "syslog" }
    
    fn parse(&self, raw: &str) -> Result<SecurityEvent, ParseError> {
        // Parse syslog format: <priority>timestamp hostname app: message
        let parts: Vec<&str> = raw.splitn(4, ' ').collect();
        if parts.len() < 4 {
            return Err(ParseError::InvalidFormat("Invalid syslog".to_string()));
        }
        
        Ok(SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::Custom,
            severity: Severity::Info,
            source: EventSource {
                system: "syslog".to_string(),
                component: parts.get(2).unwrap_or(&"unknown").to_string(),
                host: Some(parts.get(1).unwrap_or(&"").to_string()),
                ip: None,
            },
            timestamp: chrono::Utc::now(),
            description: parts.get(3).unwrap_or(&"").to_string(),
            raw_data: serde_json::json!({"raw": raw}),
            indicators: vec![],
            tags: vec!["syslog".to_string()],
            tenant_id: None,
        })
    }
}

// JSON Parser
struct JsonParser;

#[async_trait::async_trait]
impl EventParser for JsonParser {
    fn source_type(&self) -> &str { "json" }
    
    fn parse(&self, raw: &str) -> Result<SecurityEvent, ParseError> {
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| ParseError::InvalidFormat(e.to_string()))?;
        
        Ok(SecurityEvent {
            id: value.get("id").and_then(|v| v.as_str()).unwrap_or(&uuid::Uuid::new_v4().to_string()).to_string(),
            event_type: EventType::Custom,
            severity: Severity::Info,
            source: EventSource {
                system: value.get("source").and_then(|v| v.as_str()).unwrap_or("json").to_string(),
                component: value.get("component").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                host: value.get("host").and_then(|v| v.as_str()).map(|s| s.to_string()),
                ip: value.get("ip").and_then(|v| v.as_str()).map(|s| s.to_string()),
            },
            timestamp: chrono::Utc::now(),
            description: value.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            raw_data: value,
            indicators: vec![],
            tags: vec!["json".to_string()],
            tenant_id: None,
        })
    }
}

// CEF Parser
struct CefParser;

#[async_trait::async_trait]
impl EventParser for CefParser {
    fn source_type(&self) -> &str { "cef" }
    
    fn parse(&self, raw: &str) -> Result<SecurityEvent, ParseError> {
        // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
        if !raw.starts_with("CEF:") {
            return Err(ParseError::InvalidFormat("Not CEF format".to_string()));
        }
        
        let parts: Vec<&str> = raw[4..].splitn(8, '|').collect();
        if parts.len() < 7 {
            return Err(ParseError::InvalidFormat("Invalid CEF".to_string()));
        }
        
        let severity = parts[6].parse::<u8>().unwrap_or(1);
        
        Ok(SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::Custom,
            severity: match severity {
                0..=2 => Severity::Info,
                3..=4 => Severity::Low,
                5..=6 => Severity::Medium,
                7..=8 => Severity::High,
                _ => Severity::Critical,
            },
            source: EventSource {
                system: parts[1].to_string(),
                component: parts[2].to_string(),
                host: None,
                ip: None,
            },
            timestamp: chrono::Utc::now(),
            description: parts[5].to_string(),
            raw_data: serde_json::json!({"raw": raw}),
            indicators: vec![],
            tags: vec!["cef".to_string()],
            tenant_id: None,
        })
    }
}

// LEEF Parser
struct LeefParser;

#[async_trait::async_trait]
impl EventParser for LeefParser {
    fn source_type(&self) -> &str { "leef" }
    
    fn parse(&self, raw: &str) -> Result<SecurityEvent, ParseError> {
        // LEEF:Version|Vendor|Product|Version|EventID|
        if !raw.starts_with("LEEF:") {
            return Err(ParseError::InvalidFormat("Not LEEF format".to_string()));
        }
        
        Ok(SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::Custom,
            severity: Severity::Info,
            source: EventSource {
                system: "leef".to_string(),
                component: "unknown".to_string(),
                host: None,
                ip: None,
            },
            timestamp: chrono::Utc::now(),
            description: raw.to_string(),
            raw_data: serde_json::json!({"raw": raw}),
            indicators: vec![],
            tags: vec!["leef".to_string()],
            tenant_id: None,
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    UnknownSource(String),
    InvalidFormat(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSource(s) => write!(f, "Unknown source: {}", s),
            Self::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}
