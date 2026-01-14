//! Risk Assessment

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use uuid::Uuid;

/// Risk register
pub struct RiskRegister {
    risks: Arc<RwLock<HashMap<String, Risk>>>,
}

impl RiskRegister {
    pub fn new() -> Self {
        Self {
            risks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add risk
    pub fn add(&self, risk: Risk) -> String {
        let id = risk.id.to_string();
        self.risks.write().insert(id.clone(), risk);
        id
    }

    /// Get risk
    pub fn get(&self, id: &str) -> Option<Risk> {
        self.risks.read().get(id).cloned()
    }

    /// Get all risks
    pub fn all(&self) -> Vec<Risk> {
        self.risks.read().values().cloned().collect()
    }

    /// Get risks by category
    pub fn by_category(&self, category: RiskCategory) -> Vec<Risk> {
        self.risks.read()
            .values()
            .filter(|r| r.category == category)
            .cloned()
            .collect()
    }

    /// Get high risks (score >= 15)
    pub fn high_risks(&self) -> Vec<Risk> {
        self.risks.read()
            .values()
            .filter(|r| r.inherent_score >= 15)
            .cloned()
            .collect()
    }

    /// Update risk
    pub fn update(&self, id: &str, f: impl FnOnce(&mut Risk)) {
        if let Some(risk) = self.risks.write().get_mut(id) {
            f(risk);
        }
    }

    /// Calculate risk summary
    pub fn summary(&self) -> RiskSummary {
        let risks = self.risks.read();
        let total = risks.len();
        let critical = risks.values().filter(|r| r.inherent_score >= 20).count();
        let high = risks.values().filter(|r| r.inherent_score >= 15 && r.inherent_score < 20).count();
        let medium = risks.values().filter(|r| r.inherent_score >= 8 && r.inherent_score < 15).count();
        let low = risks.values().filter(|r| r.inherent_score < 8).count();

        RiskSummary { total, critical, high, medium, low }
    }
}

impl Default for RiskRegister {
    fn default() -> Self { Self::new() }
}

/// Risk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub category: RiskCategory,
    pub likelihood: RiskLevel,
    pub impact: RiskLevel,
    pub inherent_score: u8,
    pub controls: Vec<String>,
    pub residual_likelihood: RiskLevel,
    pub residual_impact: RiskLevel,
    pub residual_score: u8,
    pub treatment: RiskTreatment,
    pub owner: String,
    pub review_date: chrono::NaiveDate,
    pub status: RiskStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Risk {
    /// Create new risk
    pub fn new(
        title: &str,
        description: &str,
        category: RiskCategory,
        likelihood: RiskLevel,
        impact: RiskLevel,
        owner: &str,
    ) -> Self {
        let inherent_score = likelihood as u8 * impact as u8;
        
        Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            category,
            likelihood,
            impact,
            inherent_score,
            controls: Vec::new(),
            residual_likelihood: likelihood,
            residual_impact: impact,
            residual_score: inherent_score,
            treatment: RiskTreatment::Mitigate,
            owner: owner.to_string(),
            review_date: chrono::Utc::now().date_naive() + chrono::Duration::days(90),
            status: RiskStatus::Open,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Add control
    pub fn add_control(&mut self, control_id: &str, effectiveness: u8) {
        self.controls.push(control_id.to_string());
        
        // Reduce residual based on control effectiveness
        let reduction = (effectiveness as f64 / 100.0 * self.inherent_score as f64) as u8;
        self.residual_score = self.inherent_score.saturating_sub(reduction);
        self.updated_at = chrono::Utc::now();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskCategory {
    Strategic,
    Operational,
    Financial,
    Compliance,
    Security,
    Privacy,
    Reputational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    VeryLow = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    VeryHigh = 5,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RiskTreatment {
    Accept,
    Mitigate,
    Transfer,
    Avoid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RiskStatus {
    Open,
    InProgress,
    Accepted,
    Closed,
}

/// Risk summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}
