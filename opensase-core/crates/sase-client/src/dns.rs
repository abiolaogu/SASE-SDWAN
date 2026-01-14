//! DNS Manager
//!
//! Secure DNS configuration and protection.

use std::net::IpAddr;

pub struct DnsManager {
    original_servers: parking_lot::RwLock<Vec<String>>,
    configured: parking_lot::RwLock<bool>,
}

impl DnsManager {
    pub fn new() -> Self {
        Self {
            original_servers: parking_lot::RwLock::new(Vec::new()),
            configured: parking_lot::RwLock::new(false),
        }
    }
    
    pub async fn configure(&self, servers: &[String]) -> Result<(), crate::ClientError> {
        // Save original DNS servers
        let original = self.get_current_dns().await;
        *self.original_servers.write() = original;
        
        tracing::info!("Configuring DNS servers: {:?}", servers);
        
        #[cfg(target_os = "windows")]
        self.configure_windows(servers).await?;
        
        #[cfg(target_os = "macos")]
        self.configure_macos(servers).await?;
        
        #[cfg(target_os = "linux")]
        self.configure_linux(servers).await?;
        
        *self.configured.write() = true;
        Ok(())
    }
    
    pub async fn restore(&self) -> Result<(), crate::ClientError> {
        if !*self.configured.read() {
            return Ok(());
        }
        
        let original = self.original_servers.read().clone();
        tracing::info!("Restoring original DNS servers: {:?}", original);
        
        #[cfg(target_os = "windows")]
        self.restore_windows(&original).await?;
        
        #[cfg(target_os = "macos")]
        self.restore_macos(&original).await?;
        
        #[cfg(target_os = "linux")]
        self.restore_linux(&original).await?;
        
        *self.configured.write() = false;
        Ok(())
    }
    
    async fn get_current_dns(&self) -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            // Use netsh or WMI to get current DNS
            vec![]
        }
        #[cfg(target_os = "macos")]
        {
            // Use scutil to get current DNS
            vec![]
        }
        #[cfg(target_os = "linux")]
        {
            // Read /etc/resolv.conf
            if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
                return content
                    .lines()
                    .filter(|line| line.starts_with("nameserver"))
                    .filter_map(|line| line.split_whitespace().nth(1))
                    .map(|s| s.to_string())
                    .collect();
            }
            vec![]
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            vec![]
        }
    }
    
    #[cfg(target_os = "windows")]
    async fn configure_windows(&self, servers: &[String]) -> Result<(), crate::ClientError> {
        // Use netsh to configure DNS
        // netsh interface ipv4 set dnsservers "Ethernet" static 10.0.0.1
        for server in servers {
            let output = tokio::process::Command::new("netsh")
                .args(["interface", "ipv4", "add", "dnsservers", "name=*", &format!("address={}", server)])
                .output()
                .await
                .map_err(|e| crate::ClientError::DnsFailed(e.to_string()))?;
            
            if !output.status.success() {
                tracing::warn!("Failed to set DNS: {:?}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    async fn restore_windows(&self, servers: &[String]) -> Result<(), crate::ClientError> {
        // Restore using DHCP or original servers
        let _ = tokio::process::Command::new("netsh")
            .args(["interface", "ipv4", "set", "dnsservers", "name=*", "source=dhcp"])
            .output()
            .await;
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    async fn configure_macos(&self, servers: &[String]) -> Result<(), crate::ClientError> {
        // Use scutil to configure DNS
        let dns_config = format!(
            r#"d.init
d.add ServerAddresses * {}
set State:/Network/Service/OpenSASE/DNS
quit"#,
            servers.join(" ")
        );
        
        let mut child = tokio::process::Command::new("scutil")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| crate::ClientError::DnsFailed(e.to_string()))?;
        
        if let Some(stdin) = child.stdin.as_mut() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(dns_config.as_bytes()).await
                .map_err(|e| crate::ClientError::DnsFailed(e.to_string()))?;
        }
        
        child.wait().await
            .map_err(|e| crate::ClientError::DnsFailed(e.to_string()))?;
        
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    async fn restore_macos(&self, _servers: &[String]) -> Result<(), crate::ClientError> {
        // Remove scutil DNS entry
        let _ = tokio::process::Command::new("scutil")
            .args(["--set", "State:/Network/Service/OpenSASE/DNS", ""])
            .output()
            .await;
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    async fn configure_linux(&self, servers: &[String]) -> Result<(), crate::ClientError> {
        // Check if systemd-resolved is available
        if std::path::Path::new("/run/systemd/resolve/resolv.conf").exists() {
            // Use resolvectl
            for server in servers {
                let _ = tokio::process::Command::new("resolvectl")
                    .args(["dns", "opensase0", server])
                    .output()
                    .await;
            }
        } else {
            // Modify /etc/resolv.conf
            let content = servers.iter()
                .map(|s| format!("nameserver {}", s))
                .collect::<Vec<_>>()
                .join("\n");
            
            std::fs::write("/etc/resolv.conf.opensase", &content)
                .map_err(|e| crate::ClientError::DnsFailed(e.to_string()))?;
        }
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    async fn restore_linux(&self, servers: &[String]) -> Result<(), crate::ClientError> {
        // Restore original resolv.conf
        if std::path::Path::new("/etc/resolv.conf.backup").exists() {
            std::fs::copy("/etc/resolv.conf.backup", "/etc/resolv.conf")
                .map_err(|e| crate::ClientError::DnsFailed(e.to_string()))?;
        }
        Ok(())
    }
}

impl Default for DnsManager {
    fn default() -> Self { Self::new() }
}
