//! Wazuh SIEM Adapter (ACL)
//!
//! Translates DLP alerts to Wazuh format for correlation.

use serde::{Deserialize, Serialize};

/// Wazuh adapter for SIEM integration
pub struct WazuhAdapter {
    syslog_target: String,
}

impl WazuhAdapter {
    pub fn new(syslog_target: &str) -> Self {
        Self {
            syslog_target: syslog_target.to_string(),
        }
    }

    /// Convert DLP violation to Wazuh alert
    pub fn translate_dlp_alert(
        &self,
        classifier: &str,
        severity: &str,
        source: &str,
        match_count: usize,
    ) -> WazuhAlert {
        let level = match severity.to_lowercase().as_str() {
            "critical" => 15,
            "high" => 12,
            "medium" => 8,
            "low" => 5,
            _ => 3,
        };

        WazuhAlert {
            timestamp: chrono_now(),
            rule: WazuhRule {
                level,
                description: format!("DLP: {} pattern detected", classifier),
                id: self.classifier_to_rule_id(classifier),
                groups: vec!["dlp".into(), "data_loss".into()],
            },
            agent: WazuhAgent {
                id: "000".into(),
                name: "opensase-dlp".into(),
            },
            data: WazuhData {
                classifier: classifier.into(),
                source: source.into(),
                match_count,
            },
        }
    }

    /// Convert session risk to Wazuh alert
    pub fn translate_risk_alert(
        &self,
        user_id: &str,
        risk_score: f32,
        anomaly_factors: &[String],
        action: &str,
    ) -> WazuhAlert {
        let level = if risk_score > 0.9 {
            15
        } else if risk_score > 0.7 {
            12
        } else if risk_score > 0.5 {
            8
        } else {
            5
        };

        WazuhAlert {
            timestamp: chrono_now(),
            rule: WazuhRule {
                level,
                description: format!("Behavioral anomaly: {} (risk: {:.2})", action, risk_score),
                id: 99100,
                groups: vec!["behavioral".into(), "zero_trust".into()],
            },
            agent: WazuhAgent {
                id: "000".into(),
                name: "opensase-behavioral".into(),
            },
            data: WazuhData {
                classifier: user_id.into(),
                source: anomaly_factors.join(", "),
                match_count: anomaly_factors.len(),
            },
        }
    }

    /// Format as CEF for syslog
    pub fn to_cef(&self, alert: &WazuhAlert) -> String {
        format!(
            "CEF:0|OpenSASE|SASE|1.0|{}|{}|{}|src={} cnt={} cs1={} cs1Label=classifier",
            alert.rule.id,
            alert.rule.description,
            alert.rule.level,
            alert.data.source,
            alert.data.match_count,
            alert.data.classifier,
        )
    }

    fn classifier_to_rule_id(&self, classifier: &str) -> u32 {
        match classifier {
            "ssn" => 99001,
            "credit_card" => 99002,
            "aws_access_key" | "api_key" => 99003,
            "private_key" => 99004,
            "high_entropy" => 99005,
            _ => 99099,
        }
    }
}

/// Wazuh alert format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhAlert {
    pub timestamp: String,
    pub rule: WazuhRule,
    pub agent: WazuhAgent,
    pub data: WazuhData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhRule {
    pub level: u8,
    pub description: String,
    pub id: u32,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhAgent {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhData {
    pub classifier: String,
    pub source: String,
    pub match_count: usize,
}

fn chrono_now() -> String {
    // Simplified - in production use chrono
    "2026-01-13T19:00:00Z".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlp_alert() {
        let adapter = WazuhAdapter::new("127.0.0.1:514");
        
        let alert = adapter.translate_dlp_alert(
            "credit_card",
            "high",
            "user@example.com",
            3,
        );

        assert_eq!(alert.rule.level, 12);
        assert_eq!(alert.rule.id, 99002);
        assert!(alert.rule.groups.contains(&"dlp".to_string()));
    }

    #[test]
    fn test_cef_format() {
        let adapter = WazuhAdapter::new("127.0.0.1:514");
        
        let alert = adapter.translate_dlp_alert(
            "ssn",
            "critical",
            "file.txt",
            1,
        );

        let cef = adapter.to_cef(&alert);
        assert!(cef.starts_with("CEF:0|OpenSASE"));
        assert!(cef.contains("99001"));
    }
}
