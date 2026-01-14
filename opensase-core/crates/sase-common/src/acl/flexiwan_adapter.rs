//! FlexiWAN SD-WAN Adapter (ACL)
//!
//! Translates between domain model and FlexiWAN API.

use serde::{Deserialize, Serialize};

/// FlexiWAN adapter for SD-WAN integration
pub struct FlexiWanAdapter {
    api_url: String,
    api_key: Option<String>,
}

impl FlexiWanAdapter {
    /// Create new FlexiWAN adapter
    pub fn new(api_url: &str) -> Self {
        Self {
            api_url: api_url.to_string(),
            api_key: None,
        }
    }

    /// Set API key
    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }

    /// Convert domain path recommendation to FlexiWAN policy
    pub fn translate_path_policy(
        &self,
        site: &str,
        app_class: &str,
        primary_wan: &str,
        backup_wan: Option<&str>,
    ) -> FlexiWanPolicy {
        FlexiWanPolicy {
            name: format!("{}-{}-steering", site, app_class),
            site_id: site.to_string(),
            applications: vec![FlexiWanApp {
                name: app_class.to_string(),
                classification: "dpi".to_string(),
            }],
            path_selection: FlexiWanPathSelection {
                mode: "app-based".to_string(),
                primary: primary_wan.to_string(),
                backup: backup_wan.map(String::from),
                failover: true,
            },
            priority: 100,
            enabled: true,
        }
    }

    /// Convert domain QoE thresholds to FlexiWAN SLA
    pub fn translate_sla(
        &self,
        name: &str,
        max_latency_ms: u32,
        max_jitter_ms: u32,
        max_loss_percent: f32,
    ) -> FlexiWanSla {
        FlexiWanSla {
            name: name.to_string(),
            metrics: FlexiWanMetrics {
                latency_threshold_ms: max_latency_ms,
                jitter_threshold_ms: max_jitter_ms,
                loss_threshold_percent: max_loss_percent,
            },
            action: "failover".to_string(),
        }
    }
}

/// FlexiWAN policy format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiWanPolicy {
    pub name: String,
    pub site_id: String,
    pub applications: Vec<FlexiWanApp>,
    pub path_selection: FlexiWanPathSelection,
    pub priority: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiWanApp {
    pub name: String,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiWanPathSelection {
    pub mode: String,
    pub primary: String,
    pub backup: Option<String>,
    pub failover: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiWanSla {
    pub name: String,
    pub metrics: FlexiWanMetrics,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlexiWanMetrics {
    pub latency_threshold_ms: u32,
    pub jitter_threshold_ms: u32,
    pub loss_threshold_percent: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_policy() {
        let adapter = FlexiWanAdapter::new("http://flexiwan:3000");
        
        let policy = adapter.translate_path_policy(
            "site-a",
            "voice",
            "wan1",
            Some("lte"),
        );

        assert_eq!(policy.name, "site-a-voice-steering");
        assert_eq!(policy.path_selection.primary, "wan1");
        assert_eq!(policy.path_selection.backup, Some("lte".to_string()));
    }

    #[test]
    fn test_translate_sla() {
        let adapter = FlexiWanAdapter::new("http://flexiwan:3000");
        
        let sla = adapter.translate_sla("voice-sla", 150, 30, 1.0);

        assert_eq!(sla.metrics.latency_threshold_ms, 150);
        assert_eq!(sla.metrics.loss_threshold_percent, 1.0);
    }
}
