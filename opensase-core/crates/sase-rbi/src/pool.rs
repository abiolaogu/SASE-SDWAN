//! Container Pool Management
//!
//! Pre-warmed container pool for fast session startup.

use crate::{SessionConfig, Viewport};
use crate::container::{ContainerManager, ContainerState, ContainerStatus};
use std::collections::VecDeque;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Pool of pre-warmed containers for fast startup
pub struct ContainerPool {
    /// Available pre-warmed containers
    available: parking_lot::Mutex<VecDeque<PooledContainer>>,
    /// Container manager
    manager: ContainerManager,
    /// Pool configuration
    config: PoolConfig,
    /// Statistics
    stats: PoolStats,
    /// Refill channel
    refill_tx: mpsc::Sender<()>,
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum pool size
    pub min_size: usize,
    /// Maximum pool size
    pub max_size: usize,
    /// Pre-warm batch size
    pub warm_batch_size: usize,
    /// Container idle timeout
    pub idle_timeout_secs: u64,
    /// Default viewport for pre-warmed containers
    pub default_viewport: Viewport,
    /// Container image
    pub image: String,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_size: 10,
            max_size: 100,
            warm_batch_size: 5,
            idle_timeout_secs: 300,
            default_viewport: Viewport::default(),
            image: "opensase/chromium-isolated:latest".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PooledContainer {
    pub container_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub vnc_port: u16,
    pub websocket_port: u16,
}

#[derive(Debug, Default)]
struct PoolStats {
    containers_created: std::sync::atomic::AtomicU64,
    containers_reused: std::sync::atomic::AtomicU64,
    containers_expired: std::sync::atomic::AtomicU64,
    pool_hits: std::sync::atomic::AtomicU64,
    pool_misses: std::sync::atomic::AtomicU64,
}

impl ContainerPool {
    pub fn new(config: PoolConfig) -> Self {
        let (tx, _rx) = mpsc::channel(10);
        
        Self {
            available: parking_lot::Mutex::new(VecDeque::new()),
            manager: ContainerManager::new(&config.image),
            config,
            stats: PoolStats::default(),
            refill_tx: tx,
        }
    }
    
    /// Initialize pool with pre-warmed containers
    pub async fn initialize(&self) -> Result<(), String> {
        info!("Initializing container pool with {} containers", self.config.min_size);
        
        for _ in 0..self.config.min_size {
            if let Err(e) = self.create_pooled_container().await {
                warn!("Failed to pre-warm container: {}", e);
            }
        }
        
        let available = self.available.lock().len();
        info!("Container pool initialized with {} containers", available);
        
        Ok(())
    }
    
    /// Acquire a container from the pool
    pub async fn acquire(&self, session_id: &str) -> Result<PooledContainer, String> {
        use std::sync::atomic::Ordering;
        
        // Try to get from pool
        if let Some(container) = self.available.lock().pop_front() {
            self.stats.pool_hits.fetch_add(1, Ordering::Relaxed);
            self.stats.containers_reused.fetch_add(1, Ordering::Relaxed);
            
            info!("Acquired container {} from pool for session {}", 
                  container.container_id, session_id);
            
            // Trigger refill
            let _ = self.refill_tx.try_send(());
            
            return Ok(container);
        }
        
        // Pool miss - create on demand
        self.stats.pool_misses.fetch_add(1, Ordering::Relaxed);
        
        info!("Pool miss - creating container on demand for session {}", session_id);
        self.create_pooled_container().await
    }
    
    /// Release container back to pool or destroy
    pub async fn release(&self, container: PooledContainer) {
        let pool_size = self.available.lock().len();
        
        if pool_size < self.config.max_size {
            // Return to pool after reset
            if let Err(e) = self.reset_container(&container.container_id).await {
                warn!("Failed to reset container: {}", e);
                let _ = self.destroy(&container.container_id).await;
                return;
            }
            
            self.available.lock().push_back(container);
            info!("Released container back to pool");
        } else {
            // Pool full - destroy
            let _ = self.destroy(&container.container_id).await;
        }
    }
    
    /// Destroy a container
    pub async fn destroy(&self, container_id: &str) -> Result<(), String> {
        self.manager.destroy_container(container_id).await
    }
    
    /// Get pool statistics
    pub fn get_stats(&self) -> PoolSnapshot {
        use std::sync::atomic::Ordering;
        
        PoolSnapshot {
            available: self.available.lock().len(),
            created: self.stats.containers_created.load(Ordering::Relaxed),
            reused: self.stats.containers_reused.load(Ordering::Relaxed),
            expired: self.stats.containers_expired.load(Ordering::Relaxed),
            pool_hits: self.stats.pool_hits.load(Ordering::Relaxed),
            pool_misses: self.stats.pool_misses.load(Ordering::Relaxed),
        }
    }
    
    /// Clean up expired containers
    pub fn cleanup_expired(&self) {
        use std::sync::atomic::Ordering;
        
        let cutoff = chrono::Utc::now() - 
            chrono::Duration::seconds(self.config.idle_timeout_secs as i64);
        
        let mut available = self.available.lock();
        let before = available.len();
        
        available.retain(|c| c.created_at > cutoff);
        
        let expired = before - available.len();
        if expired > 0 {
            self.stats.containers_expired.fetch_add(expired as u64, Ordering::Relaxed);
            info!("Cleaned up {} expired containers from pool", expired);
        }
    }
    
    /// Refill pool to minimum size
    pub async fn refill(&self) {
        let current = self.available.lock().len();
        
        if current < self.config.min_size {
            let needed = (self.config.min_size - current).min(self.config.warm_batch_size);
            
            info!("Refilling pool with {} containers", needed);
            
            for _ in 0..needed {
                if let Err(e) = self.create_pooled_container().await {
                    warn!("Failed to refill container: {}", e);
                }
            }
        }
    }
    
    async fn create_pooled_container(&self) -> Result<PooledContainer, String> {
        use std::sync::atomic::Ordering;
        
        let session_id = format!("pool-{}", uuid::Uuid::new_v4());
        let config = SessionConfig {
            viewport: self.config.default_viewport,
            ..Default::default()
        };
        
        let container_id = self.manager.create_container(&session_id, &config).await?;
        
        // Get port mappings
        let state = self.manager.get_state(&session_id)
            .ok_or("Container state not found")?;
        
        self.stats.containers_created.fetch_add(1, Ordering::Relaxed);
        
        Ok(PooledContainer {
            container_id,
            created_at: chrono::Utc::now(),
            vnc_port: state.vnc_port.unwrap_or(5900),
            websocket_port: state.websocket_port.unwrap_or(8080),
        })
    }
    
    async fn reset_container(&self, container_id: &str) -> Result<(), String> {
        // Navigate to blank page and clear state
        use tokio::process::Command;
        
        let output = Command::new("docker")
            .args(["exec", container_id, "chromium-reset"])
            .output()
            .await
            .map_err(|e| format!("Reset failed: {}", e))?;
        
        if !output.status.success() {
            return Err("Container reset failed".to_string());
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PoolSnapshot {
    pub available: usize,
    pub created: u64,
    pub reused: u64,
    pub expired: u64,
    pub pool_hits: u64,
    pub pool_misses: u64,
}

impl PoolSnapshot {
    /// Calculate hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.pool_hits + self.pool_misses;
        if total == 0 {
            0.0
        } else {
            self.pool_hits as f64 / total as f64
        }
    }
}

/// Background task to maintain pool
pub async fn pool_maintenance_task(pool: std::sync::Arc<ContainerPool>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        // Clean expired
        pool.cleanup_expired();
        
        // Refill
        pool.refill().await;
    }
}
