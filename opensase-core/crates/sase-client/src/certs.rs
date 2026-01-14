//! Certificate Store
//!
//! Manage TLS certificates for traffic interception.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub struct CertificateStore {
    ca_cert: parking_lot::RwLock<Option<CaCertificate>>,
    trusted_certs: parking_lot::RwLock<Vec<TrustedCertificate>>,
    store_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
    pub subject: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub installed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedCertificate {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub pinned: bool,
}

impl CertificateStore {
    pub fn new(store_path: PathBuf) -> Self {
        Self {
            ca_cert: parking_lot::RwLock::new(None),
            trusted_certs: parking_lot::RwLock::new(Vec::new()),
            store_path,
        }
    }
    
    /// Load CA certificate from server
    pub async fn fetch_ca_certificate(&self, server_url: &str) -> Result<CaCertificate, CertError> {
        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/api/v1/ca/certificate", server_url))
            .send()
            .await
            .map_err(|e| CertError::FetchFailed(e.to_string()))?;
        
        let cert: CaCertificate = response.json().await
            .map_err(|e| CertError::ParseFailed(e.to_string()))?;
        
        *self.ca_cert.write() = Some(cert.clone());
        Ok(cert)
    }
    
    /// Install CA certificate to system trust store
    pub async fn install_ca_certificate(&self) -> Result<(), CertError> {
        let ca = self.ca_cert.read().clone()
            .ok_or(CertError::NoCertificate)?;
        
        #[cfg(target_os = "windows")]
        self.install_windows(&ca).await?;
        
        #[cfg(target_os = "macos")]
        self.install_macos(&ca).await?;
        
        #[cfg(target_os = "linux")]
        self.install_linux(&ca).await?;
        
        #[cfg(any(target_os = "ios", target_os = "android"))]
        self.install_mobile(&ca).await?;
        
        // Mark as installed
        if let Some(ref mut cert) = *self.ca_cert.write() {
            cert.installed = true;
        }
        
        Ok(())
    }
    
    /// Remove CA certificate from system trust store
    pub async fn uninstall_ca_certificate(&self) -> Result<(), CertError> {
        let ca = self.ca_cert.read().clone()
            .ok_or(CertError::NoCertificate)?;
        
        #[cfg(target_os = "windows")]
        self.uninstall_windows(&ca).await?;
        
        #[cfg(target_os = "macos")]
        self.uninstall_macos(&ca).await?;
        
        #[cfg(target_os = "linux")]
        self.uninstall_linux(&ca).await?;
        
        if let Some(ref mut cert) = *self.ca_cert.write() {
            cert.installed = false;
        }
        
        Ok(())
    }
    
    /// Check if CA is installed
    pub fn is_ca_installed(&self) -> bool {
        self.ca_cert.read().as_ref().map(|c| c.installed).unwrap_or(false)
    }
    
    /// Get CA fingerprint
    pub fn get_ca_fingerprint(&self) -> Option<String> {
        self.ca_cert.read().as_ref().map(|c| c.fingerprint.clone())
    }
    
    // Platform-specific implementations
    
    #[cfg(target_os = "windows")]
    async fn install_windows(&self, ca: &CaCertificate) -> Result<(), CertError> {
        // Use certutil to install certificate
        let cert_path = self.store_path.join("opensase-ca.crt");
        std::fs::write(&cert_path, &ca.cert_pem)
            .map_err(|e| CertError::InstallFailed(e.to_string()))?;
        
        let output = tokio::process::Command::new("certutil")
            .args(["-addstore", "Root", cert_path.to_str().unwrap()])
            .output()
            .await
            .map_err(|e| CertError::InstallFailed(e.to_string()))?;
        
        if !output.status.success() {
            return Err(CertError::InstallFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    async fn uninstall_windows(&self, ca: &CaCertificate) -> Result<(), CertError> {
        let _ = tokio::process::Command::new("certutil")
            .args(["-delstore", "Root", &ca.fingerprint])
            .output()
            .await;
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    async fn install_macos(&self, ca: &CaCertificate) -> Result<(), CertError> {
        // Use security add-trusted-cert
        let cert_path = self.store_path.join("opensase-ca.crt");
        std::fs::write(&cert_path, &ca.cert_pem)
            .map_err(|e| CertError::InstallFailed(e.to_string()))?;
        
        let output = tokio::process::Command::new("security")
            .args([
                "add-trusted-cert",
                "-d",
                "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                cert_path.to_str().unwrap(),
            ])
            .output()
            .await
            .map_err(|e| CertError::InstallFailed(e.to_string()))?;
        
        if !output.status.success() {
            return Err(CertError::InstallFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    async fn uninstall_macos(&self, ca: &CaCertificate) -> Result<(), CertError> {
        let _ = tokio::process::Command::new("security")
            .args([
                "remove-trusted-cert",
                "-d",
                &format!("sha1:{}", ca.fingerprint),
            ])
            .output()
            .await;
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    async fn install_linux(&self, ca: &CaCertificate) -> Result<(), CertError> {
        // Copy to /usr/local/share/ca-certificates
        let cert_path = PathBuf::from("/usr/local/share/ca-certificates/opensase-ca.crt");
        std::fs::write(&cert_path, &ca.cert_pem)
            .map_err(|e| CertError::InstallFailed(e.to_string()))?;
        
        // Run update-ca-certificates
        let output = tokio::process::Command::new("update-ca-certificates")
            .output()
            .await
            .map_err(|e| CertError::InstallFailed(e.to_string()))?;
        
        if !output.status.success() {
            return Err(CertError::InstallFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    async fn uninstall_linux(&self, _ca: &CaCertificate) -> Result<(), CertError> {
        let _ = std::fs::remove_file("/usr/local/share/ca-certificates/opensase-ca.crt");
        let _ = tokio::process::Command::new("update-ca-certificates")
            .arg("--fresh")
            .output()
            .await;
        Ok(())
    }
    
    #[cfg(any(target_os = "ios", target_os = "android"))]
    async fn install_mobile(&self, _ca: &CaCertificate) -> Result<(), CertError> {
        // Mobile platforms require user interaction via settings
        Err(CertError::ManualInstallRequired)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("Failed to fetch certificate: {0}")]
    FetchFailed(String),
    
    #[error("Failed to parse certificate: {0}")]
    ParseFailed(String),
    
    #[error("No certificate available")]
    NoCertificate,
    
    #[error("Failed to install certificate: {0}")]
    InstallFailed(String),
    
    #[error("Manual installation required")]
    ManualInstallRequired,
}
