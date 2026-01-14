//! Evidence Collection and Storage

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use uuid::Uuid;

/// Evidence store (immutable, append-only)
pub struct EvidenceStore {
    evidence: Arc<RwLock<Vec<Evidence>>>,
}

impl EvidenceStore {
    pub fn new() -> Self {
        Self {
            evidence: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add evidence
    pub fn add(&self, evidence: Evidence) -> String {
        let id = evidence.id.clone();
        self.evidence.write().push(evidence);
        id
    }

    /// Get evidence by ID
    pub fn get(&self, id: &str) -> Option<Evidence> {
        self.evidence.read().iter().find(|e| e.id == id).cloned()
    }

    /// Get evidence for control
    pub fn for_control(&self, control_id: &str) -> Vec<Evidence> {
        self.evidence.read()
            .iter()
            .filter(|e| e.control_ids.contains(&control_id.to_string()))
            .cloned()
            .collect()
    }

    /// Get evidence count
    pub fn count(&self) -> usize {
        self.evidence.read().len()
    }

    /// Export evidence package
    pub fn export(&self, framework: &str) -> EvidencePackage {
        let evidence: Vec<_> = self.evidence.read()
            .iter()
            .filter(|e| e.framework == framework)
            .cloned()
            .collect();

        EvidencePackage {
            id: Uuid::new_v4().to_string(),
            framework: framework.to_string(),
            generated_at: chrono::Utc::now(),
            evidence,
            signature: String::new(), // In production: sign package
        }
    }
}

impl Default for EvidenceStore {
    fn default() -> Self { Self::new() }
}

/// Evidence record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub evidence_type: EvidenceType,
    pub framework: String,
    pub control_ids: Vec<String>,
    pub title: String,
    pub description: String,
    pub collected_at: chrono::DateTime<chrono::Utc>,
    pub collector: CollectorType,
    pub content: EvidenceContent,
    pub hash: String,
    pub retention_until: chrono::DateTime<chrono::Utc>,
}

impl Evidence {
    /// Create new evidence
    pub fn new(
        evidence_type: EvidenceType,
        framework: &str,
        control_ids: Vec<String>,
        title: &str,
        content: EvidenceContent,
    ) -> Self {
        let content_bytes = serde_json::to_vec(&content).unwrap_or_default();
        let hash = hex::encode(Sha256::digest(&content_bytes));
        
        Self {
            id: Uuid::new_v4().to_string(),
            evidence_type,
            framework: framework.to_string(),
            control_ids,
            title: title.to_string(),
            description: String::new(),
            collected_at: chrono::Utc::now(),
            collector: CollectorType::Automated,
            content,
            hash,
            retention_until: chrono::Utc::now() + chrono::Duration::days(365 * 7),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EvidenceType {
    ConfigSnapshot,
    AccessLog,
    ChangeRecord,
    ScanResult,
    TrainingRecord,
    PolicyDocument,
    ApprovalRecord,
    Screenshot,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CollectorType {
    Automated,
    Manual,
    Api,
}

/// Evidence content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EvidenceContent {
    Text { text: String },
    Json { data: serde_json::Value },
    File { filename: String, size_bytes: u64, hash: String },
    Screenshot { path: String, description: String },
}

/// Evidence package for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub id: String,
    pub framework: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub evidence: Vec<Evidence>,
    pub signature: String,
}
