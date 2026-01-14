//! Repositories - Persistence abstraction for aggregates
//!
//! Repository pattern:
//! - Abstracts persistence details
//! - Works with whole aggregates
//! - Supports unit of work pattern

use super::aggregates::*;
use super::value_objects::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Repository result type
pub type RepoResult<T> = Result<T, RepositoryError>;

/// Repository errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum RepositoryError {
    #[error("not found: {0}")]
    NotFound(String),
    
    #[error("conflict: {0}")]
    Conflict(String),
    
    #[error("storage error: {0}")]
    StorageError(String),
}

/// Policy Repository trait
#[async_trait]
pub trait PolicyRepository: Send + Sync {
    /// Get policy by ID
    async fn get(&self, id: &PolicyId) -> RepoResult<PolicyAggregate>;
    
    /// Save policy
    async fn save(&self, policy: &PolicyAggregate) -> RepoResult<()>;
    
    /// Delete policy
    async fn delete(&self, id: &PolicyId) -> RepoResult<()>;
    
    /// List all policies
    async fn list(&self) -> RepoResult<Vec<PolicyId>>;
}

/// In-memory policy repository (for testing and development)
pub struct InMemoryPolicyRepository {
    policies: RwLock<HashMap<String, PolicyAggregate>>,
}

impl InMemoryPolicyRepository {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryPolicyRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyRepository for InMemoryPolicyRepository {
    async fn get(&self, id: &PolicyId) -> RepoResult<PolicyAggregate> {
        self.policies
            .read()
            .get(id.as_str())
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(id.to_string()))
    }

    async fn save(&self, policy: &PolicyAggregate) -> RepoResult<()> {
        self.policies
            .write()
            .insert(policy.id().to_string(), policy.clone());
        Ok(())
    }

    async fn delete(&self, id: &PolicyId) -> RepoResult<()> {
        self.policies
            .write()
            .remove(id.as_str())
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(id.to_string()))
    }

    async fn list(&self) -> RepoResult<Vec<PolicyId>> {
        let ids: Vec<_> = self.policies
            .read()
            .keys()
            .filter_map(|k| PolicyId::new(k.clone()).ok())
            .collect();
        Ok(ids)
    }
}

/// Session Repository trait
#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn get(&self, id: &str) -> RepoResult<SessionAggregate>;
    async fn save(&self, session: &SessionAggregate) -> RepoResult<()>;
    async fn delete(&self, id: &str) -> RepoResult<()>;
    async fn get_by_user(&self, user_id: &UserId) -> RepoResult<Vec<SessionAggregate>>;
}

/// In-memory session repository
pub struct InMemorySessionRepository {
    sessions: RwLock<HashMap<String, SessionAggregate>>,
}

impl InMemorySessionRepository {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySessionRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionRepository for InMemorySessionRepository {
    async fn get(&self, id: &str) -> RepoResult<SessionAggregate> {
        self.sessions
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(id.to_string()))
    }

    async fn save(&self, session: &SessionAggregate) -> RepoResult<()> {
        self.sessions
            .write()
            .insert(session.id().to_string(), session.clone());
        Ok(())
    }

    async fn delete(&self, id: &str) -> RepoResult<()> {
        self.sessions
            .write()
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(id.to_string()))
    }

    async fn get_by_user(&self, user_id: &UserId) -> RepoResult<Vec<SessionAggregate>> {
        let sessions: Vec<_> = self.sessions
            .read()
            .values()
            .filter(|s| s.user_id() == user_id)
            .cloned()
            .collect();
        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_repository() {
        let repo = InMemoryPolicyRepository::new();
        
        let id = PolicyId::new("test-policy").unwrap();
        let policy = PolicyAggregate::new(id.clone(), Action::Deny);

        // Save
        repo.save(&policy).await.unwrap();

        // Get
        let retrieved = repo.get(&id).await.unwrap();
        assert_eq!(retrieved.id().as_str(), "test-policy");

        // List
        let list = repo.list().await.unwrap();
        assert_eq!(list.len(), 1);

        // Delete
        repo.delete(&id).await.unwrap();
        assert!(repo.get(&id).await.is_err());
    }

    #[tokio::test]
    async fn test_session_repository() {
        let repo = InMemorySessionRepository::new();
        
        let user = UserId::new("user1").unwrap();
        let session = SessionAggregate::new("sess1".into(), user.clone());

        // Save
        repo.save(&session).await.unwrap();

        // Get
        let retrieved = repo.get("sess1").await.unwrap();
        assert_eq!(retrieved.user_id().as_str(), "user1");

        // Get by user
        let sessions = repo.get_by_user(&user).await.unwrap();
        assert_eq!(sessions.len(), 1);
    }
}
