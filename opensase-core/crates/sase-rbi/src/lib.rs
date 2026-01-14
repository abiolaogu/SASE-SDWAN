//! OpenSASE Browser Isolation (OSBI)
//!
//! Remote Browser Isolation platform that executes web browsing in secure
//! containers at the PoP, streaming only safe pixels/DOM to end users.
//!
//! # Features
//! - Pixel-push streaming for maximum security
//! - DOM reconstruction for performance-sensitive scenarios
//! - Chromium-based isolated browsing
//! - Full input/output isolation
//!
//! # Architecture
//! ```text
//! User Device                    PoP Edge                      Internet
//! ┌──────────┐    WebRTC/WSS    ┌─────────────────────┐       ┌─────────┐
//! │ RBI      │ ◄─────────────►  │ Container Orchestrator │     │ Target  │
//! │ Client   │   Pixels/Events  │ ┌─────────────────┐   │     │ Website │
//! │          │                  │ │ Chromium        │ ◄─┼────►│         │
//! │          │                  │ │ Sandbox         │   │     │         │
//! └──────────┘                  │ └─────────────────┘   │     └─────────┘
//!                               └─────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

pub mod container;
pub mod streaming;
pub mod policy;
pub mod session;
pub mod input;
pub mod download;
pub mod swg;
pub mod pool;
pub mod encoder;
pub mod gateway;

// =============================================================================
// Session Types
// =============================================================================

/// Unique browser isolation session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationSession {
    pub id: String,
    pub user_id: String,
    pub container_id: String,
    pub pop_location: String,
    pub mode: IsolationMode,
    pub status: SessionStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub config: SessionConfig,
    pub metrics: SessionMetrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationMode {
    /// Stream raw pixels (H.264/VP9 encoded)
    PixelPush,
    /// Stream sanitized DOM for reconstruction
    DomReconstruction,
    /// Hybrid: DOM with pixel fallback for complex elements
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Creating,
    Initializing,
    Ready,
    Active,
    Paused,
    Terminating,
    Terminated,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Target URL for isolation
    pub initial_url: Option<String>,
    /// Viewport dimensions
    pub viewport: Viewport,
    /// Enable file downloads (with scanning)
    pub downloads_enabled: bool,
    /// Enable clipboard (with DLP)
    pub clipboard_enabled: bool,
    /// Enable printing
    pub print_enabled: bool,
    /// Session timeout
    pub timeout: Duration,
    /// Max memory per container
    pub max_memory_mb: u32,
    /// Max CPU cores
    pub max_cpu_cores: f32,
    /// Allowed domains (if restricted)
    pub allowed_domains: Vec<String>,
    /// Blocked domains
    pub blocked_domains: Vec<String>,
    /// Data loss prevention rules
    pub dlp_rules: Vec<String>,
    /// Enable session recording
    pub recording_enabled: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            initial_url: None,
            viewport: Viewport::default(),
            downloads_enabled: true,
            clipboard_enabled: true,
            print_enabled: false,
            timeout: Duration::from_secs(3600), // 1 hour
            max_memory_mb: 2048,
            max_cpu_cores: 2.0,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            dlp_rules: Vec::new(),
            recording_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
    pub scale: f32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            scale: 1.0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMetrics {
    pub bytes_streamed: u64,
    pub frames_sent: u64,
    pub events_received: u64,
    pub pages_visited: u64,
    pub downloads_scanned: u64,
    pub threats_blocked: u64,
    pub latency_ms: f64,
    pub bandwidth_kbps: f64,
}

// =============================================================================
// Container Types
// =============================================================================

/// Browser container specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub image: String,
    pub memory_limit: String,
    pub cpu_limit: String,
    pub security_opts: Vec<String>,
    pub capabilities: ContainerCapabilities,
    pub network_policy: NetworkPolicy,
}

impl Default for ContainerSpec {
    fn default() -> Self {
        Self {
            image: "opensase/chromium-isolated:latest".to_string(),
            memory_limit: "2Gi".to_string(),
            cpu_limit: "2".to_string(),
            security_opts: vec![
                "no-new-privileges:true".to_string(),
                "seccomp:chromium.json".to_string(),
            ],
            capabilities: ContainerCapabilities::minimal(),
            network_policy: NetworkPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerCapabilities {
    pub drop: Vec<String>,
    pub add: Vec<String>,
}

impl ContainerCapabilities {
    pub fn minimal() -> Self {
        Self {
            drop: vec!["ALL".to_string()],
            add: vec![
                "SYS_ADMIN".to_string(), // Required for Chromium sandbox
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Allow outbound to internet
    pub allow_internet: bool,
    /// Allowed destination CIDRs
    pub allowed_cidrs: Vec<String>,
    /// Blocked destination CIDRs
    pub blocked_cidrs: Vec<String>,
    /// DNS servers to use
    pub dns_servers: Vec<String>,
    /// Enable DNS filtering
    pub dns_filtering: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow_internet: true,
            allowed_cidrs: Vec::new(),
            blocked_cidrs: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            dns_filtering: true,
        }
    }
}

// =============================================================================
// Streaming Types
// =============================================================================

/// Frame encoding for pixel streaming
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoCodec {
    H264,
    VP9,
    AV1,
}

/// Streaming configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub codec: VideoCodec,
    pub max_fps: u32,
    pub max_bitrate_kbps: u32,
    pub quality: StreamQuality,
    pub keyframe_interval: u32,
    pub enable_audio: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            codec: VideoCodec::H264,
            max_fps: 30,
            max_bitrate_kbps: 5000,
            quality: StreamQuality::High,
            keyframe_interval: 60,
            enable_audio: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamQuality {
    Low,
    Medium,
    High,
    Ultra,
}

/// DOM reconstruction element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomElement {
    pub id: String,
    pub tag: String,
    pub attributes: HashMap<String, String>,
    pub styles: HashMap<String, String>,
    pub text: Option<String>,
    pub children: Vec<String>,
    pub bounding_box: BoundingBox,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

/// DOM update for incremental sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomUpdate {
    Add { parent_id: String, element: DomElement },
    Remove { element_id: String },
    Modify { element_id: String, changes: HashMap<String, String> },
    Scroll { x: f32, y: f32 },
    Navigate { url: String },
}

// =============================================================================
// Input Types
// =============================================================================

/// User input event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputEvent {
    MouseMove { x: f32, y: f32 },
    MouseDown { x: f32, y: f32, button: MouseButton },
    MouseUp { x: f32, y: f32, button: MouseButton },
    Click { x: f32, y: f32, button: MouseButton },
    DoubleClick { x: f32, y: f32 },
    Scroll { x: f32, y: f32, delta_x: f32, delta_y: f32 },
    KeyDown { key: String, code: String, modifiers: Modifiers },
    KeyUp { key: String, code: String, modifiers: Modifiers },
    KeyPress { key: String, code: String, modifiers: Modifiers },
    Paste { text: String },
    Copy,
    Cut,
    TouchStart { touches: Vec<Touch> },
    TouchMove { touches: Vec<Touch> },
    TouchEnd { touches: Vec<Touch> },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Modifiers {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub meta: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Touch {
    pub id: u32,
    pub x: f32,
    pub y: f32,
}

// =============================================================================
// RBI Service
// =============================================================================

/// Main RBI service
pub struct BrowserIsolationService {
    config: ServiceConfig,
    container_manager: container::ContainerManager,
    sessions: dashmap::DashMap<String, IsolationSession>,
    stream_manager: streaming::StreamManager,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Session timeout
    pub session_timeout: Duration,
    /// Container image
    pub container_image: String,
    /// Default isolation mode
    pub default_mode: IsolationMode,
    /// Enable malware scanning
    pub malware_scanning: bool,
    /// Pop location
    pub pop_location: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_timeout: Duration::from_secs(3600),
            container_image: "opensase/chromium-isolated:latest".to_string(),
            default_mode: IsolationMode::PixelPush,
            malware_scanning: true,
            pop_location: "unknown".to_string(),
        }
    }
}

impl BrowserIsolationService {
    pub fn new(config: ServiceConfig) -> Self {
        Self {
            config: config.clone(),
            container_manager: container::ContainerManager::new(&config.container_image),
            sessions: dashmap::DashMap::new(),
            stream_manager: streaming::StreamManager::new(),
        }
    }
    
    /// Create new isolation session
    pub async fn create_session(
        &self,
        user_id: &str,
        config: SessionConfig,
    ) -> Result<IsolationSession, String> {
        // Check capacity
        if self.sessions.len() >= self.config.max_sessions {
            return Err("Maximum sessions reached".to_string());
        }
        
        let session_id = uuid::Uuid::new_v4().to_string();
        
        // Create container
        let container_id = self.container_manager
            .create_container(&session_id, &config)
            .await?;
        
        let session = IsolationSession {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            container_id,
            pop_location: self.config.pop_location.clone(),
            mode: self.config.default_mode,
            status: SessionStatus::Creating,
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            config,
            metrics: SessionMetrics::default(),
        };
        
        self.sessions.insert(session_id, session.clone());
        
        Ok(session)
    }
    
    /// Get session by ID
    pub fn get_session(&self, session_id: &str) -> Option<IsolationSession> {
        self.sessions.get(session_id).map(|s| s.clone())
    }
    
    /// Terminate session
    pub async fn terminate_session(&self, session_id: &str) -> Result<(), String> {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            self.container_manager.destroy_container(&session.container_id).await?;
        }
        Ok(())
    }
    
    /// Handle input event
    pub async fn handle_input(
        &self,
        session_id: &str,
        event: InputEvent,
    ) -> Result<(), String> {
        let session = self.sessions.get(session_id)
            .ok_or("Session not found")?;
        
        // Validate and sanitize input
        let sanitized = self.sanitize_input(&event)?;
        
        // Forward to container
        self.container_manager
            .send_input(&session.container_id, sanitized)
            .await
    }
    
    /// Get active session count
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }
    
    fn sanitize_input(&self, event: &InputEvent) -> Result<InputEvent, String> {
        match event {
            InputEvent::Paste { text } => {
                // Check DLP rules
                if text.len() > 100_000 {
                    return Err("Paste content too large".to_string());
                }
                Ok(event.clone())
            }
            _ => Ok(event.clone()),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert!(config.downloads_enabled);
        assert_eq!(config.max_memory_mb, 2048);
    }
    
    #[test]
    fn test_container_capabilities() {
        let caps = ContainerCapabilities::minimal();
        assert!(caps.drop.contains(&"ALL".to_string()));
    }
    
    #[test]
    fn test_viewport_default() {
        let vp = Viewport::default();
        assert_eq!(vp.width, 1920);
        assert_eq!(vp.height, 1080);
    }
}
