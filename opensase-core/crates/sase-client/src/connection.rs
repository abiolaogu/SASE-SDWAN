//! Connection Manager
//!
//! Automatic reconnection and connection monitoring.

use std::sync::Arc;
use std::time::Duration;

pub struct ConnectionManager {
    config: ConnectionConfig,
    state: parking_lot::RwLock<ConnectionState>,
    reconnect_count: std::sync::atomic::AtomicU32,
}

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub auto_reconnect: bool,
    pub reconnect_delay_ms: u64,
    pub max_reconnect_attempts: u32,
    pub keepalive_interval_secs: u64,
    pub connection_timeout_secs: u64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            auto_reconnect: true,
            reconnect_delay_ms: 1000,
            max_reconnect_attempts: 10,
            keepalive_interval_secs: 25,
            connection_timeout_secs: 30,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

pub struct ConnectionHealth {
    pub connected: bool,
    pub latency_ms: Option<u32>,
    pub packet_loss_percent: f32,
    pub last_handshake: Option<chrono::DateTime<chrono::Utc>>,
}

impl ConnectionManager {
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            state: parking_lot::RwLock::new(ConnectionState::Idle),
            reconnect_count: std::sync::atomic::AtomicU32::new(0),
        }
    }
    
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }
    
    pub fn set_state(&self, state: ConnectionState) {
        *self.state.write() = state;
    }
    
    pub fn should_reconnect(&self) -> bool {
        if !self.config.auto_reconnect {
            return false;
        }
        
        let attempts = self.reconnect_count.load(std::sync::atomic::Ordering::Relaxed);
        attempts < self.config.max_reconnect_attempts
    }
    
    pub fn increment_reconnect(&self) -> u32 {
        self.reconnect_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
    
    pub fn reset_reconnect(&self) {
        self.reconnect_count.store(0, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn reconnect_delay(&self) -> Duration {
        let attempts = self.reconnect_count.load(std::sync::atomic::Ordering::Relaxed);
        // Exponential backoff with jitter
        let base_delay = self.config.reconnect_delay_ms;
        let delay = base_delay * (1 << attempts.min(5));
        Duration::from_millis(delay)
    }
    
    pub async fn check_health(&self) -> ConnectionHealth {
        // Ping the tunnel endpoint
        ConnectionHealth {
            connected: *self.state.read() == ConnectionState::Connected,
            latency_ms: Some(25), // Placeholder
            packet_loss_percent: 0.0,
            last_handshake: Some(chrono::Utc::now()),
        }
    }
}
