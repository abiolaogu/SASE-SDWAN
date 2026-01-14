//! ML-Powered Application Classification

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Application classifier
pub struct AppClassifier {
    /// Known signatures (port/protocol → app)
    signatures: HashMap<(u16, u8), AppSignature>,
    /// ML model weights (simplified decision tree)
    model: ClassificationModel,
}

impl AppClassifier {
    /// Create new classifier
    pub fn new() -> Self {
        let mut c = Self {
            signatures: HashMap::new(),
            model: ClassificationModel::default(),
        };
        c.load_default_signatures();
        c
    }

    fn load_default_signatures(&mut self) {
        // Voice/Video
        self.add_signature(5060, 17, "SIP", AppCategory::VoiceVideo);
        self.add_signature(5061, 6, "SIP-TLS", AppCategory::VoiceVideo);
        self.add_signature(3478, 17, "STUN", AppCategory::VoiceVideo);
        self.add_signature(3479, 17, "TURN", AppCategory::VoiceVideo);
        
        // Interactive
        self.add_signature(443, 6, "HTTPS", AppCategory::Interactive);
        self.add_signature(80, 6, "HTTP", AppCategory::Interactive);
        self.add_signature(22, 6, "SSH", AppCategory::Interactive);
        self.add_signature(3389, 6, "RDP", AppCategory::Interactive);
        
        // Bulk transfer
        self.add_signature(21, 6, "FTP", AppCategory::Bulk);
        self.add_signature(20, 6, "FTP-Data", AppCategory::Bulk);
        self.add_signature(445, 6, "SMB", AppCategory::Bulk);
        
        // Background
        self.add_signature(123, 17, "NTP", AppCategory::Background);
        self.add_signature(53, 17, "DNS", AppCategory::Background);
    }

    fn add_signature(&mut self, port: u16, protocol: u8, name: &str, category: AppCategory) {
        self.signatures.insert((port, protocol), AppSignature {
            name: name.to_string(),
            category,
            traffic_class: category.traffic_class(),
        });
    }

    /// Classify by port/protocol
    pub fn classify_by_port(&self, port: u16, protocol: u8) -> Option<&AppSignature> {
        self.signatures.get(&(port, protocol))
    }

    /// Classify using ML model
    pub fn classify_ml(&self, features: &FlowFeatures) -> ClassificationResult {
        // Decision tree logic
        
        // High packet rate + small packets = Voice/Video
        if features.avg_packet_size < 300.0 && features.packets_per_sec > 20.0 {
            return ClassificationResult {
                category: AppCategory::VoiceVideo,
                confidence: 0.85,
                app_name: None,
            };
        }

        // Large packets + low rate = Bulk
        if features.avg_packet_size > 1200.0 && features.packets_per_sec < 10.0 {
            return ClassificationResult {
                category: AppCategory::Bulk,
                confidence: 0.80,
                app_name: None,
            };
        }

        // Medium packets + interactive timing = Interactive
        if features.inter_arrival_variance < 100.0 && features.bidirectional {
            return ClassificationResult {
                category: AppCategory::Interactive,
                confidence: 0.75,
                app_name: None,
            };
        }

        // Default to background
        ClassificationResult {
            category: AppCategory::Background,
            confidence: 0.60,
            app_name: None,
        }
    }

    /// Classify by DPI (deep packet inspection)
    pub fn classify_dpi(&self, payload: &[u8]) -> Option<ClassificationResult> {
        if payload.is_empty() { return None; }

        // HTTP detection
        if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") 
            || payload.starts_with(b"HTTP/") {
            return Some(ClassificationResult {
                category: AppCategory::Interactive,
                confidence: 0.95,
                app_name: Some("HTTP".into()),
            });
        }

        // TLS detection (check for ClientHello)
        if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
            // Extract SNI if possible
            let sni = extract_sni(payload);
            let category = self.categorize_domain(sni.as_deref());
            return Some(ClassificationResult {
                category,
                confidence: 0.90,
                app_name: sni,
            });
        }

        // DNS detection
        if payload.len() > 12 && (payload[2] & 0x80) == 0 {
            // Could be DNS query
            return Some(ClassificationResult {
                category: AppCategory::Background,
                confidence: 0.70,
                app_name: Some("DNS".into()),
            });
        }

        None
    }

    fn categorize_domain(&self, domain: Option<&str>) -> AppCategory {
        let domain = match domain {
            Some(d) => d,
            None => return AppCategory::Interactive,
        };

        // SaaS categorization
        if domain.contains("zoom.") || domain.contains("teams.") 
            || domain.contains("webex.") || domain.contains("meet.") {
            AppCategory::VoiceVideo
        } else if domain.contains("office365.") || domain.contains("salesforce.")
            || domain.contains("workday.") {
            AppCategory::Interactive
        } else if domain.contains("dropbox.") || domain.contains("box.") 
            || domain.contains("onedrive.") {
            AppCategory::Bulk
        } else {
            AppCategory::Interactive
        }
    }

    /// Full classification pipeline
    pub fn classify(&self, port: u16, protocol: u8, features: &FlowFeatures, payload: &[u8]) -> ClassificationResult {
        // 1. Try signature-based (fastest)
        if let Some(sig) = self.classify_by_port(port, protocol) {
            return ClassificationResult {
                category: sig.category,
                confidence: 0.99,
                app_name: Some(sig.name.clone()),
            };
        }

        // 2. Try DPI
        if let Some(result) = self.classify_dpi(payload) {
            return result;
        }

        // 3. Fall back to ML
        self.classify_ml(features)
    }
}

impl Default for AppClassifier {
    fn default() -> Self { Self::new() }
}

/// Application category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppCategory {
    /// Voice/Video - latency-sensitive
    VoiceVideo,
    /// Interactive - moderate latency tolerance
    Interactive,
    /// Bulk transfer - bandwidth-sensitive
    Bulk,
    /// Background - best effort
    Background,
}

impl AppCategory {
    /// Get traffic class
    pub fn traffic_class(&self) -> TrafficClass {
        match self {
            Self::VoiceVideo => TrafficClass::Expedited,
            Self::Interactive => TrafficClass::Assured,
            Self::Bulk => TrafficClass::Bulk,
            Self::Background => TrafficClass::BestEffort,
        }
    }

    /// Get DSCP value
    pub fn dscp(&self) -> u8 {
        match self {
            Self::VoiceVideo => 46,    // EF
            Self::Interactive => 26,   // AF31
            Self::Bulk => 10,          // AF11
            Self::Background => 0,     // BE
        }
    }

    /// Get latency SLA (ms)
    pub fn latency_sla(&self) -> u32 {
        match self {
            Self::VoiceVideo => 50,
            Self::Interactive => 150,
            Self::Bulk => 500,
            Self::Background => 1000,
        }
    }
}

/// Traffic class for QoS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Expedited,    // EF - Voice/Video
    Assured,      // AF - Interactive
    Bulk,         // Low priority bulk
    BestEffort,   // Default
}

/// Application signature
#[derive(Debug, Clone)]
pub struct AppSignature {
    pub name: String,
    pub category: AppCategory,
    pub traffic_class: TrafficClass,
}

/// Flow features for ML classification
#[derive(Debug, Clone, Default)]
pub struct FlowFeatures {
    pub avg_packet_size: f64,
    pub packets_per_sec: f64,
    pub inter_arrival_variance: f64,
    pub bidirectional: bool,
    pub total_bytes: u64,
    pub duration_secs: f64,
}

/// Classification result
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub category: AppCategory,
    pub confidence: f64,
    pub app_name: Option<String>,
}

/// ML classification model (simplified)
#[derive(Debug, Clone, Default)]
pub struct ClassificationModel {
    // Would contain actual model weights
    _placeholder: (),
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    // Simplified SNI extraction from TLS ClientHello
    if payload.len() < 43 { return None; }
    if payload[0] != 0x16 { return None; }  // Not handshake
    
    // Skip to extensions and find SNI
    // This is a simplified implementation
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len { return None; }
    
    // Search for SNI extension (type 0x0000)
    // In production, properly parse TLS extensions
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_classification() {
        let classifier = AppClassifier::new();
        
        let sip = classifier.classify_by_port(5060, 17).unwrap();
        assert_eq!(sip.category, AppCategory::VoiceVideo);
        
        let https = classifier.classify_by_port(443, 6).unwrap();
        assert_eq!(https.category, AppCategory::Interactive);
    }

    #[test]
    fn test_ml_classification() {
        let classifier = AppClassifier::new();
        
        // Voice-like traffic
        let voice_features = FlowFeatures {
            avg_packet_size: 200.0,
            packets_per_sec: 50.0,
            inter_arrival_variance: 5.0,
            bidirectional: true,
            total_bytes: 10000,
            duration_secs: 10.0,
        };
        
        let result = classifier.classify_ml(&voice_features);
        assert_eq!(result.category, AppCategory::VoiceVideo);
    }

    #[test]
    fn test_dscp_values() {
        assert_eq!(AppCategory::VoiceVideo.dscp(), 46);
        assert_eq!(AppCategory::Interactive.dscp(), 26);
    }
}
