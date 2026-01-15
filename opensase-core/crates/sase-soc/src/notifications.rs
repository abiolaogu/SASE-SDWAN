//! Multi-Channel Notification System
//!
//! Enhanced notification capabilities adapted from Email repository.
//! Complements existing sase-soc alerts with escalation and templating.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Notification channel
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotificationChannel {
    Email,
    Sms,
    Slack,
    MsTeams,
    PagerDuty,
    Webhook,
    InApp,
}

/// Escalation policy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub id: String,
    pub name: String,
    pub levels: Vec<EscalationLevel>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscalationLevel {
    pub level: u8,
    pub delay_minutes: u32,
    pub recipients: Vec<String>,
    pub channels: Vec<NotificationChannel>,
}

/// Notification template
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationTemplate {
    pub id: String,
    pub name: String,
    pub channel: NotificationChannel,
    pub subject: String,
    pub body: String,
    pub variables: Vec<String>,
}

/// Notification request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationRequest {
    pub template_id: String,
    pub recipients: Vec<String>,
    pub variables: HashMap<String, String>,
    pub escalation_policy_id: Option<String>,
    pub priority: NotificationPriority,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NotificationPriority { Low, Normal, High, Urgent }

/// Notification manager
pub struct NotificationManager {
    templates: HashMap<String, NotificationTemplate>,
    policies: HashMap<String, EscalationPolicy>,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
            policies: HashMap::new(),
        }
    }
    
    pub fn register_template(&mut self, template: NotificationTemplate) {
        self.templates.insert(template.id.clone(), template);
    }
    
    pub fn register_policy(&mut self, policy: EscalationPolicy) {
        self.policies.insert(policy.id.clone(), policy);
    }
    
    pub async fn send(&self, request: NotificationRequest) -> Result<(), NotificationError> {
        let template = self.templates.get(&request.template_id)
            .ok_or(NotificationError::TemplateNotFound)?;
        
        // Render template with variables
        let mut body = template.body.clone();
        for (key, value) in &request.variables {
            body = body.replace(&format!("{{{{{}}}}}", key), value);
        }
        
        // In production, dispatch to actual channels
        Ok(())
    }
}

impl Default for NotificationManager {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Template not found")]
    TemplateNotFound,
    #[error("Delivery failed")]
    DeliveryFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_notification_manager() {
        let mut manager = NotificationManager::new();
        manager.register_template(NotificationTemplate {
            id: "threat".into(),
            name: "Threat Alert".into(),
            channel: NotificationChannel::Email,
            subject: "Threat Detected".into(),
            body: "A {{severity}} threat was detected.".into(),
            variables: vec!["severity".into()],
        });
        
        assert!(manager.templates.contains_key("threat"));
    }
}
