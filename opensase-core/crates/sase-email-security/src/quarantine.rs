//! Quarantine Management
//!
//! Email quarantine storage, review, and release functionality.

use crate::{EmailMessage, EmailVerdict, VerdictAction, ThreatCategory};
use std::collections::HashMap;

/// Quarantine manager
pub struct QuarantineManager {
    /// Quarantined messages
    messages: dashmap::DashMap<String, QuarantinedMessage>,
    /// Retention days
    retention_days: u32,
    /// Max quarantine size
    max_size: usize,
}

#[derive(Debug, Clone)]
pub struct QuarantinedMessage {
    pub id: String,
    pub message: EmailMessage,
    pub verdict: EmailVerdict,
    pub quarantined_at: chrono::DateTime<chrono::Utc>,
    pub status: QuarantineStatus,
    pub reviewed_by: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineStatus {
    Pending,
    Released,
    Deleted,
    Expired,
}

#[derive(Debug, Clone)]
pub struct QuarantineQuery {
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub subject_contains: Option<String>,
    pub categories: Vec<ThreatCategory>,
    pub status: Option<QuarantineStatus>,
    pub from_date: Option<chrono::DateTime<chrono::Utc>>,
    pub to_date: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for QuarantineQuery {
    fn default() -> Self {
        Self {
            sender: None,
            recipient: None,
            subject_contains: None,
            categories: Vec::new(),
            status: None,
            from_date: None,
            to_date: None,
            limit: 50,
            offset: 0,
        }
    }
}

impl QuarantineManager {
    pub fn new(retention_days: u32) -> Self {
        Self {
            messages: dashmap::DashMap::new(),
            retention_days,
            max_size: 100_000,
        }
    }
    
    /// Add message to quarantine
    pub fn quarantine(&self, message: EmailMessage, verdict: EmailVerdict) -> String {
        let id = message.id.clone();
        
        let quarantined = QuarantinedMessage {
            id: id.clone(),
            message,
            verdict,
            quarantined_at: chrono::Utc::now(),
            status: QuarantineStatus::Pending,
            reviewed_by: None,
            notes: Vec::new(),
        };
        
        self.messages.insert(id.clone(), quarantined);
        
        // Cleanup if over size limit
        if self.messages.len() > self.max_size {
            self.cleanup_oldest();
        }
        
        id
    }
    
    /// Get quarantined message
    pub fn get(&self, id: &str) -> Option<QuarantinedMessage> {
        self.messages.get(id).map(|m| m.clone())
    }
    
    /// Search quarantine
    pub fn search(&self, query: &QuarantineQuery) -> Vec<QuarantinedMessage> {
        let mut results: Vec<_> = self.messages.iter()
            .filter(|entry| {
                let msg = entry.value();
                
                // Filter by sender
                if let Some(sender) = &query.sender {
                    if !msg.message.envelope.mail_from.contains(sender) {
                        return false;
                    }
                }
                
                // Filter by recipient
                if let Some(recipient) = &query.recipient {
                    if !msg.message.envelope.rcpt_to.iter().any(|r| r.contains(recipient)) {
                        return false;
                    }
                }
                
                // Filter by subject
                if let Some(subject) = &query.subject_contains {
                    if !msg.message.headers.subject.to_lowercase()
                        .contains(&subject.to_lowercase()) {
                        return false;
                    }
                }
                
                // Filter by categories
                if !query.categories.is_empty() {
                    if !msg.verdict.categories.iter()
                        .any(|c| query.categories.contains(c)) {
                        return false;
                    }
                }
                
                // Filter by status
                if let Some(status) = query.status {
                    if msg.status != status {
                        return false;
                    }
                }
                
                // Filter by date
                if let Some(from) = query.from_date {
                    if msg.quarantined_at < from {
                        return false;
                    }
                }
                
                if let Some(to) = query.to_date {
                    if msg.quarantined_at > to {
                        return false;
                    }
                }
                
                true
            })
            .map(|entry| entry.value().clone())
            .collect();
        
        // Sort by date descending
        results.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        
        // Apply pagination
        results.into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect()
    }
    
    /// Release message from quarantine
    pub fn release(&self, id: &str, reviewer: &str) -> Result<(), QuarantineError> {
        let mut entry = self.messages.get_mut(id)
            .ok_or(QuarantineError::NotFound)?;
        
        if entry.status != QuarantineStatus::Pending {
            return Err(QuarantineError::AlreadyProcessed);
        }
        
        entry.status = QuarantineStatus::Released;
        entry.reviewed_by = Some(reviewer.to_string());
        
        // Would trigger actual email delivery here
        
        Ok(())
    }
    
    /// Delete message from quarantine
    pub fn delete(&self, id: &str, reviewer: &str) -> Result<(), QuarantineError> {
        let mut entry = self.messages.get_mut(id)
            .ok_or(QuarantineError::NotFound)?;
        
        entry.status = QuarantineStatus::Deleted;
        entry.reviewed_by = Some(reviewer.to_string());
        
        Ok(())
    }
    
    /// Add note to quarantined message
    pub fn add_note(&self, id: &str, note: &str) -> Result<(), QuarantineError> {
        let mut entry = self.messages.get_mut(id)
            .ok_or(QuarantineError::NotFound)?;
        
        entry.notes.push(note.to_string());
        
        Ok(())
    }
    
    /// Cleanup expired messages
    pub fn cleanup_expired(&self) -> usize {
        let now = chrono::Utc::now();
        let retention = chrono::Duration::days(self.retention_days as i64);
        
        let expired: Vec<String> = self.messages.iter()
            .filter(|entry| {
                now - entry.value().quarantined_at > retention
            })
            .map(|entry| entry.key().clone())
            .collect();
        
        let count = expired.len();
        
        for id in expired {
            self.messages.remove(&id);
        }
        
        count
    }
    
    fn cleanup_oldest(&self) {
        // Remove oldest 10% when over capacity
        let to_remove = self.max_size / 10;
        
        let mut items: Vec<_> = self.messages.iter()
            .map(|e| (e.key().clone(), e.value().quarantined_at))
            .collect();
        
        items.sort_by(|a, b| a.1.cmp(&b.1));
        
        for (id, _) in items.into_iter().take(to_remove) {
            self.messages.remove(&id);
        }
    }
    
    /// Get quarantine statistics
    pub fn stats(&self) -> QuarantineStats {
        let mut stats = QuarantineStats::default();
        
        for entry in self.messages.iter() {
            stats.total += 1;
            
            match entry.status {
                QuarantineStatus::Pending => stats.pending += 1,
                QuarantineStatus::Released => stats.released += 1,
                QuarantineStatus::Deleted => stats.deleted += 1,
                QuarantineStatus::Expired => stats.expired += 1,
            }
            
            for category in &entry.verdict.categories {
                *stats.by_category.entry(*category).or_insert(0) += 1;
            }
        }
        
        stats
    }
}

#[derive(Debug, Default)]
pub struct QuarantineStats {
    pub total: usize,
    pub pending: usize,
    pub released: usize,
    pub deleted: usize,
    pub expired: usize,
    pub by_category: HashMap<ThreatCategory, usize>,
}

#[derive(Debug)]
pub enum QuarantineError {
    NotFound,
    AlreadyProcessed,
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Message not found"),
            Self::AlreadyProcessed => write!(f, "Message already processed"),
        }
    }
}

impl std::error::Error for QuarantineError {}
