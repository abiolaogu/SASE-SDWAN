//! Download Handling
//!
//! File download scanning and isolation.

use std::path::PathBuf;

/// Download manager with malware scanning
pub struct DownloadManager {
    config: DownloadConfig,
    scanner: MalwareScanner,
    pending: dashmap::DashMap<String, PendingDownload>,
}

#[derive(Debug, Clone)]
pub struct DownloadConfig {
    /// Max file size (bytes)
    pub max_file_size: u64,
    /// Allowed file extensions
    pub allowed_extensions: Vec<String>,
    /// Blocked file extensions
    pub blocked_extensions: Vec<String>,
    /// Enable malware scanning
    pub malware_scanning: bool,
    /// Sandbox executable downloads
    pub sandbox_executables: bool,
    /// Storage path
    pub storage_path: PathBuf,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100 MB
            allowed_extensions: Vec::new(),
            blocked_extensions: vec![
                "exe".to_string(), "msi".to_string(), "bat".to_string(),
                "cmd".to_string(), "ps1".to_string(), "vbs".to_string(),
                "js".to_string(), "jar".to_string(), "scr".to_string(),
            ],
            malware_scanning: true,
            sandbox_executables: true,
            storage_path: PathBuf::from("/var/lib/osbi/downloads"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingDownload {
    pub id: String,
    pub session_id: String,
    pub url: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
    pub status: DownloadStatus,
    pub scan_result: Option<ScanResult>,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadStatus {
    Pending,
    Downloading,
    Scanning,
    Ready,
    Blocked,
    Expired,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub clean: bool,
    pub threats: Vec<ThreatInfo>,
    pub scan_time_ms: u64,
    pub scanner_version: String,
}

#[derive(Debug, Clone)]
pub struct ThreatInfo {
    pub name: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
}

#[derive(Debug, Clone, Copy)]
pub enum ThreatCategory {
    Virus,
    Trojan,
    Ransomware,
    Spyware,
    Adware,
    Phishing,
    Exploit,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl DownloadManager {
    pub fn new(config: DownloadConfig) -> Self {
        Self {
            config,
            scanner: MalwareScanner::new(),
            pending: dashmap::DashMap::new(),
        }
    }
    
    /// Initiate download
    pub async fn start_download(
        &self,
        session_id: &str,
        url: &str,
        filename: &str,
        size: u64,
        mime_type: &str,
    ) -> Result<String, DownloadError> {
        // Check size
        if size > self.config.max_file_size {
            return Err(DownloadError::TooLarge(size, self.config.max_file_size));
        }
        
        // Check extension
        let ext = filename.split('.').last().unwrap_or("").to_lowercase();
        
        if self.config.blocked_extensions.contains(&ext) {
            return Err(DownloadError::BlockedType(ext));
        }
        
        if !self.config.allowed_extensions.is_empty() &&
           !self.config.allowed_extensions.contains(&ext) {
            return Err(DownloadError::NotAllowed(ext));
        }
        
        let download_id = uuid::Uuid::new_v4().to_string();
        
        let pending = PendingDownload {
            id: download_id.clone(),
            session_id: session_id.to_string(),
            url: url.to_string(),
            filename: filename.to_string(),
            size,
            mime_type: mime_type.to_string(),
            status: DownloadStatus::Pending,
            scan_result: None,
            started_at: chrono::Utc::now(),
        };
        
        self.pending.insert(download_id.clone(), pending);
        
        Ok(download_id)
    }
    
    /// Scan downloaded file
    pub async fn scan(&self, download_id: &str, data: &[u8]) -> Result<ScanResult, DownloadError> {
        let mut download = self.pending.get_mut(download_id)
            .ok_or(DownloadError::NotFound)?;
        
        download.status = DownloadStatus::Scanning;
        
        let result = self.scanner.scan(data, &download.filename).await;
        
        download.scan_result = Some(result.clone());
        download.status = if result.clean {
            DownloadStatus::Ready
        } else {
            DownloadStatus::Blocked
        };
        
        Ok(result)
    }
    
    /// Get download status
    pub fn get_status(&self, download_id: &str) -> Option<PendingDownload> {
        self.pending.get(download_id).map(|d| d.clone())
    }
    
    /// Approve download for user
    pub fn approve(&self, download_id: &str) -> Result<PathBuf, DownloadError> {
        let download = self.pending.get(download_id)
            .ok_or(DownloadError::NotFound)?;
        
        if download.status != DownloadStatus::Ready {
            return Err(DownloadError::NotReady);
        }
        
        // Generate safe path
        let safe_name = sanitize_filename(&download.filename);
        let path = self.config.storage_path.join(&download.id).join(safe_name);
        
        Ok(path)
    }
    
    /// Clean up expired downloads
    pub fn cleanup(&self) {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
        
        self.pending.retain(|_, d| d.started_at > cutoff);
    }
}

impl Default for DownloadManager {
    fn default() -> Self {
        Self::new(DownloadConfig::default())
    }
}

/// Malware scanner interface
struct MalwareScanner {
    engine: String,
}

impl MalwareScanner {
    fn new() -> Self {
        Self {
            engine: "ClamAV".to_string(),
        }
    }
    
    async fn scan(&self, data: &[u8], filename: &str) -> ScanResult {
        let start = std::time::Instant::now();
        
        // In production, this would call actual AV engine
        // Check for EICAR test string
        let is_eicar = std::str::from_utf8(data)
            .map(|s| s.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"))
            .unwrap_or(false);
        
        ScanResult {
            clean: !is_eicar,
            threats: if is_eicar {
                vec![ThreatInfo {
                    name: "EICAR-Test-File".to_string(),
                    category: ThreatCategory::Virus,
                    severity: ThreatSeverity::Low,
                }]
            } else {
                Vec::new()
            },
            scan_time_ms: start.elapsed().as_millis() as u64,
            scanner_version: "ClamAV 1.0".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DownloadError {
    TooLarge(u64, u64),
    BlockedType(String),
    NotAllowed(String),
    NotFound,
    NotReady,
    ScanFailed(String),
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(size, max) => write!(f, "File too large: {} > {}", size, max),
            Self::BlockedType(ext) => write!(f, "Blocked file type: {}", ext),
            Self::NotAllowed(ext) => write!(f, "File type not allowed: {}", ext),
            Self::NotFound => write!(f, "Download not found"),
            Self::NotReady => write!(f, "Download not ready"),
            Self::ScanFailed(e) => write!(f, "Scan failed: {}", e),
        }
    }
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}
