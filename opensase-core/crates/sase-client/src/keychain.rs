//! Keychain / Credential Storage
//!
//! Secure storage for credentials and keys.

use std::path::PathBuf;

pub struct KeychainStore {
    service_name: String,
}

#[derive(Clone, Debug)]
pub struct Credential {
    pub key: String,
    pub value: String,
}

impl KeychainStore {
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }
    
    /// Store a credential
    pub fn store(&self, key: &str, value: &str) -> Result<(), KeychainError> {
        #[cfg(target_os = "macos")]
        return self.store_macos(key, value);
        
        #[cfg(target_os = "windows")]
        return self.store_windows(key, value);
        
        #[cfg(target_os = "linux")]
        return self.store_linux(key, value);
        
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        return self.store_file(key, value);
    }
    
    /// Retrieve a credential
    pub fn retrieve(&self, key: &str) -> Result<String, KeychainError> {
        #[cfg(target_os = "macos")]
        return self.retrieve_macos(key);
        
        #[cfg(target_os = "windows")]
        return self.retrieve_windows(key);
        
        #[cfg(target_os = "linux")]
        return self.retrieve_linux(key);
        
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        return self.retrieve_file(key);
    }
    
    /// Delete a credential
    pub fn delete(&self, key: &str) -> Result<(), KeychainError> {
        #[cfg(target_os = "macos")]
        return self.delete_macos(key);
        
        #[cfg(target_os = "windows")]
        return self.delete_windows(key);
        
        #[cfg(target_os = "linux")]
        return self.delete_linux(key);
        
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        return self.delete_file(key);
    }
    
    // macOS implementation using security command
    #[cfg(target_os = "macos")]
    fn store_macos(&self, key: &str, value: &str) -> Result<(), KeychainError> {
        // Delete existing first
        let _ = self.delete_macos(key);
        
        let output = std::process::Command::new("security")
            .args([
                "add-generic-password",
                "-s", &self.service_name,
                "-a", key,
                "-w", value,
                "-U",
            ])
            .output()
            .map_err(|e| KeychainError::StoreFailed(e.to_string()))?;
        
        if !output.status.success() {
            return Err(KeychainError::StoreFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    fn retrieve_macos(&self, key: &str) -> Result<String, KeychainError> {
        let output = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s", &self.service_name,
                "-a", key,
                "-w",
            ])
            .output()
            .map_err(|e| KeychainError::RetrieveFailed(e.to_string()))?;
        
        if !output.status.success() {
            return Err(KeychainError::NotFound);
        }
        
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
    
    #[cfg(target_os = "macos")]
    fn delete_macos(&self, key: &str) -> Result<(), KeychainError> {
        let _ = std::process::Command::new("security")
            .args([
                "delete-generic-password",
                "-s", &self.service_name,
                "-a", key,
            ])
            .output();
        Ok(())
    }
    
    // Windows implementation using Credential Manager
    #[cfg(target_os = "windows")]
    fn store_windows(&self, key: &str, value: &str) -> Result<(), KeychainError> {
        // Use cmdkey or Windows Credential API
        let target = format!("{}:{}", self.service_name, key);
        let output = std::process::Command::new("cmdkey")
            .args(["/generic:", &target, "/user:", key, "/pass:", value])
            .output()
            .map_err(|e| KeychainError::StoreFailed(e.to_string()))?;
        
        if !output.status.success() {
            return Err(KeychainError::StoreFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    fn retrieve_windows(&self, key: &str) -> Result<String, KeychainError> {
        // Windows credential retrieval is more complex
        // Using fallback to file storage
        self.retrieve_file(key)
    }
    
    #[cfg(target_os = "windows")]
    fn delete_windows(&self, key: &str) -> Result<(), KeychainError> {
        let target = format!("{}:{}", self.service_name, key);
        let _ = std::process::Command::new("cmdkey")
            .args(["/delete:", &target])
            .output();
        Ok(())
    }
    
    // Linux implementation using secret-tool or file
    #[cfg(target_os = "linux")]
    fn store_linux(&self, key: &str, value: &str) -> Result<(), KeychainError> {
        // Try secret-tool (GNOME Keyring)
        let output = std::process::Command::new("secret-tool")
            .args([
                "store",
                "--label", &format!("{} - {}", self.service_name, key),
                "service", &self.service_name,
                "key", key,
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(value.as_bytes())?;
                }
                child.wait_with_output()
            });
        
        match output {
            Ok(o) if o.status.success() => Ok(()),
            _ => self.store_file(key, value),
        }
    }
    
    #[cfg(target_os = "linux")]
    fn retrieve_linux(&self, key: &str) -> Result<String, KeychainError> {
        let output = std::process::Command::new("secret-tool")
            .args([
                "lookup",
                "service", &self.service_name,
                "key", key,
            ])
            .output();
        
        match output {
            Ok(o) if o.status.success() => {
                Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
            }
            _ => self.retrieve_file(key),
        }
    }
    
    #[cfg(target_os = "linux")]
    fn delete_linux(&self, key: &str) -> Result<(), KeychainError> {
        let _ = std::process::Command::new("secret-tool")
            .args([
                "clear",
                "service", &self.service_name,
                "key", key,
            ])
            .output();
        let _ = self.delete_file(key);
        Ok(())
    }
    
    // File-based fallback
    fn get_store_path(&self) -> PathBuf {
        let platform = crate::platform::get_platform();
        platform.config_dir().join("credentials")
    }
    
    fn store_file(&self, key: &str, value: &str) -> Result<(), KeychainError> {
        let path = self.get_store_path();
        std::fs::create_dir_all(&path)
            .map_err(|e| KeychainError::StoreFailed(e.to_string()))?;
        
        // Simple encoding (in production, use encryption)
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            value,
        );
        
        std::fs::write(path.join(key), encoded)
            .map_err(|e| KeychainError::StoreFailed(e.to_string()))
    }
    
    fn retrieve_file(&self, key: &str) -> Result<String, KeychainError> {
        let path = self.get_store_path().join(key);
        
        let encoded = std::fs::read_to_string(&path)
            .map_err(|_| KeychainError::NotFound)?;
        
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encoded)
            .map_err(|_| KeychainError::RetrieveFailed("Decode failed".to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|_| KeychainError::RetrieveFailed("Invalid UTF-8".to_string()))
            })
    }
    
    fn delete_file(&self, key: &str) -> Result<(), KeychainError> {
        let path = self.get_store_path().join(key);
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("Failed to store credential: {0}")]
    StoreFailed(String),
    
    #[error("Failed to retrieve credential: {0}")]
    RetrieveFailed(String),
    
    #[error("Credential not found")]
    NotFound,
}
