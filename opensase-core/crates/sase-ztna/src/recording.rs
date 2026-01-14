//! Enhanced Session Recording
//!
//! Comprehensive session recording for compliance and forensics.

use crate::Session;
use std::collections::HashMap;

/// Enhanced session recorder
pub struct EnhancedSessionRecorder {
    recordings: dashmap::DashMap<String, Recording>,
    activities: dashmap::DashMap<String, Vec<RecordedActivity>>,
    encoder: RecordingEncoder,
}

#[derive(Clone)]
pub struct Recording {
    pub id: String,
    pub session_id: String,
    pub user_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub recording_type: RecordingType,
    pub metadata: RecordingMetadata,
    pub status: RecordingStatus,
    pub size_bytes: u64,
}

#[derive(Clone)]
pub struct RecordingMetadata {
    pub device_id: String,
    pub apps_accessed: Vec<String>,
    pub resources_accessed: Vec<String>,
    pub commands_executed: u32,
    pub files_transferred: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecordingType {
    Full,           // Everything
    KeystrokeOnly,  // Just keystrokes
    ScreenOnly,     // Just screen
    Network,        // Network traffic
    Commands,       // Commands only
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecordingStatus {
    Active,
    Completed,
    Failed,
    Archived,
}

#[derive(Clone)]
pub enum RecordedActivity {
    Keystroke(KeystrokeData),
    ScreenFrame(ScreenFrameData),
    Command(CommandData),
    FileAccess(FileAccessData),
    NetworkPacket(NetworkPacketData),
    ClipboardAction(ClipboardData),
}

#[derive(Clone)]
pub struct KeystrokeData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub key_code: u32,
    pub modifiers: u8,
    pub application: String,
}

#[derive(Clone)]
pub struct ScreenFrameData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub width: u32,
    pub height: u32,
    pub frame_type: FrameType,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy)]
pub enum FrameType {
    KeyFrame,
    Delta,
}

#[derive(Clone)]
pub struct CommandData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub command: String,
    pub working_dir: String,
    pub exit_code: Option<i32>,
}

#[derive(Clone)]
pub struct FileAccessData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub operation: FileOperation,
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy)]
pub enum FileOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    Upload,
    Download,
}

#[derive(Clone)]
pub struct NetworkPacketData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub direction: PacketDirection,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub size: u32,
}

#[derive(Clone, Copy)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

#[derive(Clone)]
pub struct ClipboardData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub operation: ClipboardOperation,
    pub content_type: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy)]
pub enum ClipboardOperation {
    Copy,
    Paste,
}

struct RecordingEncoder;

impl EnhancedSessionRecorder {
    pub fn new() -> Self {
        Self {
            recordings: dashmap::DashMap::new(),
            activities: dashmap::DashMap::new(),
            encoder: RecordingEncoder,
        }
    }
    
    /// Start recording session
    pub async fn start(&self, session: &Session, recording_type: RecordingType) -> String {
        let recording = Recording {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
            user_id: session.identity.user_id.clone(),
            started_at: chrono::Utc::now(),
            ended_at: None,
            recording_type,
            metadata: RecordingMetadata {
                device_id: session.device.id.clone(),
                apps_accessed: Vec::new(),
                resources_accessed: Vec::new(),
                commands_executed: 0,
                files_transferred: 0,
            },
            status: RecordingStatus::Active,
            size_bytes: 0,
        };
        
        let id = recording.id.clone();
        self.recordings.insert(id.clone(), recording);
        self.activities.insert(id.clone(), Vec::new());
        
        tracing::info!(
            "Started {:?} recording {} for session {}",
            recording_type, id, session.id
        );
        
        id
    }
    
    /// Record activity
    pub async fn record(&self, recording_id: &str, activity: RecordedActivity) {
        if let Some(mut activities) = self.activities.get_mut(recording_id) {
            // Update metadata
            if let Some(mut recording) = self.recordings.get_mut(recording_id) {
                match &activity {
                    RecordedActivity::Command(_) => {
                        recording.metadata.commands_executed += 1;
                    }
                    RecordedActivity::FileAccess(f) => {
                        if matches!(f.operation, FileOperation::Upload | FileOperation::Download) {
                            recording.metadata.files_transferred += 1;
                        }
                    }
                    RecordedActivity::ScreenFrame(f) => {
                        recording.size_bytes += f.data.len() as u64;
                    }
                    _ => {}
                }
            }
            
            activities.push(activity);
        }
    }
    
    /// Record keystroke
    pub async fn record_keystroke(
        &self,
        recording_id: &str,
        key_code: u32,
        modifiers: u8,
        application: &str,
    ) {
        self.record(recording_id, RecordedActivity::Keystroke(KeystrokeData {
            timestamp: chrono::Utc::now(),
            key_code,
            modifiers,
            application: application.to_string(),
        })).await;
    }
    
    /// Record command execution
    pub async fn record_command(
        &self,
        recording_id: &str,
        command: &str,
        working_dir: &str,
        exit_code: Option<i32>,
    ) {
        self.record(recording_id, RecordedActivity::Command(CommandData {
            timestamp: chrono::Utc::now(),
            command: command.to_string(),
            working_dir: working_dir.to_string(),
            exit_code,
        })).await;
    }
    
    /// Record file access
    pub async fn record_file_access(
        &self,
        recording_id: &str,
        operation: FileOperation,
        path: &str,
        size_bytes: u64,
    ) {
        self.record(recording_id, RecordedActivity::FileAccess(FileAccessData {
            timestamp: chrono::Utc::now(),
            operation,
            path: path.to_string(),
            size_bytes,
        })).await;
    }
    
    /// Stop recording
    pub async fn stop(&self, recording_id: &str) {
        if let Some(mut recording) = self.recordings.get_mut(recording_id) {
            recording.ended_at = Some(chrono::Utc::now());
            recording.status = RecordingStatus::Completed;
            
            let duration = recording.ended_at.unwrap() - recording.started_at;
            tracing::info!(
                "Stopped recording {} after {} seconds, {} bytes",
                recording_id, duration.num_seconds(), recording.size_bytes
            );
        }
    }
    
    /// Generate replay stream
    pub async fn get_replay(&self, recording_id: &str) -> Option<ReplayData> {
        let recording = self.recordings.get(recording_id)?.clone();
        let activities = self.activities.get(recording_id)?.clone();
        
        Some(ReplayData {
            recording,
            activities,
        })
    }
    
    /// Search recordings
    pub fn search(&self, query: RecordingQuery) -> Vec<Recording> {
        self.recordings.iter()
            .filter(|r| {
                if let Some(user_id) = &query.user_id {
                    if &r.user_id != user_id {
                        return false;
                    }
                }
                if let Some(from) = query.from_time {
                    if r.started_at < from {
                        return false;
                    }
                }
                if let Some(to) = query.to_time {
                    if r.started_at > to {
                        return false;
                    }
                }
                true
            })
            .map(|r| r.clone())
            .take(query.limit)
            .collect()
    }
}

impl Default for EnhancedSessionRecorder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReplayData {
    pub recording: Recording,
    pub activities: Vec<RecordedActivity>,
}

#[derive(Default)]
pub struct RecordingQuery {
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub from_time: Option<chrono::DateTime<chrono::Utc>>,
    pub to_time: Option<chrono::DateTime<chrono::Utc>>,
    pub recording_type: Option<RecordingType>,
    pub limit: usize,
}

impl RecordingQuery {
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }
}
