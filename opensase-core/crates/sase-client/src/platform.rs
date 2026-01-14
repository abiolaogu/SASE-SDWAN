//! Platform Abstraction Layer
//!
//! Cross-platform system operations.

use std::path::PathBuf;

/// Platform-specific operations trait
#[async_trait::async_trait]
pub trait PlatformOps: Send + Sync {
    /// Get config directory
    fn config_dir(&self) -> PathBuf;
    
    /// Get log directory
    fn log_dir(&self) -> PathBuf;
    
    /// Check if running as admin/root
    fn is_elevated(&self) -> bool;
    
    /// Request elevation if needed
    async fn request_elevation(&self) -> Result<(), PlatformError>;
    
    /// Install system service
    async fn install_service(&self) -> Result<(), PlatformError>;
    
    /// Uninstall system service
    async fn uninstall_service(&self) -> Result<(), PlatformError>;
    
    /// Start at login
    async fn enable_autostart(&self) -> Result<(), PlatformError>;
    
    /// Disable start at login
    async fn disable_autostart(&self) -> Result<(), PlatformError>;
    
    /// Show system notification
    async fn show_notification(&self, title: &str, message: &str) -> Result<(), PlatformError>;
    
    /// Set system tray icon
    async fn set_tray_icon(&self, icon: TrayIcon) -> Result<(), PlatformError>;
}

#[derive(Clone, Copy, Debug)]
pub enum TrayIcon {
    Connected,
    Disconnected,
    Connecting,
    Error,
}

/// Get platform-specific implementation
pub fn get_platform() -> Box<dyn PlatformOps> {
    #[cfg(target_os = "windows")]
    { Box::new(WindowsPlatform::new()) }
    
    #[cfg(target_os = "macos")]
    { Box::new(MacOsPlatform::new()) }
    
    #[cfg(target_os = "linux")]
    { Box::new(LinuxPlatform::new()) }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    { Box::new(GenericPlatform::new()) }
}

// Windows Platform
#[cfg(target_os = "windows")]
pub struct WindowsPlatform;

#[cfg(target_os = "windows")]
impl WindowsPlatform {
    pub fn new() -> Self { Self }
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl PlatformOps for WindowsPlatform {
    fn config_dir(&self) -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("OpenSASE")
    }
    
    fn log_dir(&self) -> PathBuf {
        self.config_dir().join("logs")
    }
    
    fn is_elevated(&self) -> bool {
        // Check for admin rights
        false
    }
    
    async fn request_elevation(&self) -> Result<(), PlatformError> {
        // ShellExecute with runas
        Ok(())
    }
    
    async fn install_service(&self) -> Result<(), PlatformError> {
        // Use sc.exe to install Windows service
        Ok(())
    }
    
    async fn uninstall_service(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    
    async fn enable_autostart(&self) -> Result<(), PlatformError> {
        // Add to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
        Ok(())
    }
    
    async fn disable_autostart(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    
    async fn show_notification(&self, title: &str, message: &str) -> Result<(), PlatformError> {
        // Use Windows Toast notifications
        Ok(())
    }
    
    async fn set_tray_icon(&self, icon: TrayIcon) -> Result<(), PlatformError> {
        Ok(())
    }
}

// macOS Platform
#[cfg(target_os = "macos")]
pub struct MacOsPlatform;

#[cfg(target_os = "macos")]
impl MacOsPlatform {
    pub fn new() -> Self { Self }
}

#[cfg(target_os = "macos")]
#[async_trait::async_trait]
impl PlatformOps for MacOsPlatform {
    fn config_dir(&self) -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/Library/Application Support"))
            .join("OpenSASE")
    }
    
    fn log_dir(&self) -> PathBuf {
        PathBuf::from("/Library/Logs/OpenSASE")
    }
    
    fn is_elevated(&self) -> bool {
        nix::unistd::geteuid().is_root()
    }
    
    async fn request_elevation(&self) -> Result<(), PlatformError> {
        // Use osascript for elevation prompt
        Ok(())
    }
    
    async fn install_service(&self) -> Result<(), PlatformError> {
        // Install launchd plist
        Ok(())
    }
    
    async fn uninstall_service(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    
    async fn enable_autostart(&self) -> Result<(), PlatformError> {
        // Add LaunchAgent plist
        Ok(())
    }
    
    async fn disable_autostart(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    
    async fn show_notification(&self, title: &str, message: &str) -> Result<(), PlatformError> {
        // Use osascript for notifications
        let _ = tokio::process::Command::new("osascript")
            .args(["-e", &format!(
                r#"display notification "{}" with title "{}""#,
                message, title
            )])
            .output()
            .await;
        Ok(())
    }
    
    async fn set_tray_icon(&self, icon: TrayIcon) -> Result<(), PlatformError> {
        Ok(())
    }
}

// Linux Platform
#[cfg(target_os = "linux")]
pub struct LinuxPlatform;

#[cfg(target_os = "linux")]
impl LinuxPlatform {
    pub fn new() -> Self { Self }
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl PlatformOps for LinuxPlatform {
    fn config_dir(&self) -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/etc"))
            .join("opensase")
    }
    
    fn log_dir(&self) -> PathBuf {
        PathBuf::from("/var/log/opensase")
    }
    
    fn is_elevated(&self) -> bool {
        nix::unistd::geteuid().is_root()
    }
    
    async fn request_elevation(&self) -> Result<(), PlatformError> {
        // Use pkexec
        Ok(())
    }
    
    async fn install_service(&self) -> Result<(), PlatformError> {
        // Install systemd service
        let service = r#"[Unit]
Description=OpenSASE Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/opensase-client daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#;
        std::fs::write("/etc/systemd/system/opensase.service", service)
            .map_err(|e| PlatformError::ServiceError(e.to_string()))?;
        
        let _ = tokio::process::Command::new("systemctl")
            .args(["daemon-reload"])
            .output()
            .await;
        
        Ok(())
    }
    
    async fn uninstall_service(&self) -> Result<(), PlatformError> {
        let _ = tokio::process::Command::new("systemctl")
            .args(["stop", "opensase"])
            .output()
            .await;
        let _ = std::fs::remove_file("/etc/systemd/system/opensase.service");
        Ok(())
    }
    
    async fn enable_autostart(&self) -> Result<(), PlatformError> {
        // Add .desktop file to autostart
        Ok(())
    }
    
    async fn disable_autostart(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    
    async fn show_notification(&self, title: &str, message: &str) -> Result<(), PlatformError> {
        let _ = tokio::process::Command::new("notify-send")
            .args([title, message])
            .output()
            .await;
        Ok(())
    }
    
    async fn set_tray_icon(&self, icon: TrayIcon) -> Result<(), PlatformError> {
        Ok(())
    }
}

// Generic Platform (fallback)
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub struct GenericPlatform;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
impl GenericPlatform {
    pub fn new() -> Self { Self }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
#[async_trait::async_trait]
impl PlatformOps for GenericPlatform {
    fn config_dir(&self) -> PathBuf { PathBuf::from(".") }
    fn log_dir(&self) -> PathBuf { PathBuf::from("./logs") }
    fn is_elevated(&self) -> bool { false }
    async fn request_elevation(&self) -> Result<(), PlatformError> { Ok(()) }
    async fn install_service(&self) -> Result<(), PlatformError> { Ok(()) }
    async fn uninstall_service(&self) -> Result<(), PlatformError> { Ok(()) }
    async fn enable_autostart(&self) -> Result<(), PlatformError> { Ok(()) }
    async fn disable_autostart(&self) -> Result<(), PlatformError> { Ok(()) }
    async fn show_notification(&self, _: &str, _: &str) -> Result<(), PlatformError> { Ok(()) }
    async fn set_tray_icon(&self, _: TrayIcon) -> Result<(), PlatformError> { Ok(()) }
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("Service error: {0}")]
    ServiceError(String),
    
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error("Not supported")]
    NotSupported,
}
