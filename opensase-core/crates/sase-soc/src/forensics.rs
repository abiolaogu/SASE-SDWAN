//! Forensics Collection
//!
//! Evidence collection and chain of custody.

use std::collections::HashMap;

pub struct ForensicsCollector {
    collections: dashmap::DashMap<String, ForensicCollection>,
    evidence: dashmap::DashMap<String, Evidence>,
}

#[derive(Clone, serde::Serialize)]
pub struct ForensicCollection {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub status: CollectionStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub collected_by: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Copy, serde::Serialize, PartialEq, Eq)]
pub enum CollectionStatus { Pending, InProgress, Completed, Failed }

#[derive(Clone, serde::Serialize)]
pub struct Evidence {
    pub id: String,
    pub collection_id: String,
    pub evidence_type: EvidenceType,
    pub source_host: String,
    pub hash_sha256: String,
    pub size_bytes: u64,
    pub collected_at: chrono::DateTime<chrono::Utc>,
    pub chain_of_custody: Vec<CustodyEvent>,
    pub storage_path: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Clone, Copy, serde::Serialize, PartialEq, Eq)]
pub enum EvidenceType {
    MemoryDump, DiskImage, LogFile, NetworkCapture,
    ProcessList, Registry, FileArtifact, MalwareSample,
}

#[derive(Clone, serde::Serialize)]
pub struct CustodyEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: String,
    pub actor: String,
    pub notes: Option<String>,
}

impl ForensicsCollector {
    pub fn new() -> Self {
        Self {
            collections: dashmap::DashMap::new(),
            evidence: dashmap::DashMap::new(),
        }
    }
    
    pub async fn create_collection(&self, case_id: &str, name: &str, actor: &str) -> String {
        let collection = ForensicCollection {
            id: uuid::Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            name: name.to_string(),
            status: CollectionStatus::Pending,
            created_at: chrono::Utc::now(),
            completed_at: None,
            collected_by: actor.to_string(),
            evidence_ids: vec![],
        };
        let id = collection.id.clone();
        self.collections.insert(id.clone(), collection);
        id
    }
    
    pub async fn add_evidence(&self, collection_id: &str, evidence: Evidence) {
        self.evidence.insert(evidence.id.clone(), evidence.clone());
        if let Some(mut c) = self.collections.get_mut(collection_id) {
            c.evidence_ids.push(evidence.id);
        }
    }
    
    pub fn get_collection(&self, id: &str) -> Option<ForensicCollection> {
        self.collections.get(id).map(|c| c.clone())
    }
    
    pub fn get_evidence(&self, id: &str) -> Option<Evidence> {
        self.evidence.get(id).map(|e| e.clone())
    }
}

impl Default for ForensicsCollector {
    fn default() -> Self { Self::new() }
}
