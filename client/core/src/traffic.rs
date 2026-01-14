//! Traffic Interception

use crate::ClientError;
use std::sync::Arc;
use parking_lot::RwLock;

/// Traffic interceptor
pub struct TrafficInterceptor {
    mode: Arc<RwLock<TunnelMode>>,
    active: Arc<RwLock<bool>>,
}

impl TrafficInterceptor {
    pub fn new() -> Self {
        Self {
            mode: Arc::new(RwLock::new(TunnelMode::FullTunnel)),
            active: Arc::new(RwLock::new(false)),
        }
    }

    /// Enable traffic interception
    pub async fn enable(&self, mode: TunnelMode) -> Result<(), ClientError> {
        tracing::info!("Enabling traffic interception: {:?}", mode);
        
        *self.mode.write() = mode;

        match mode {
            TunnelMode::FullTunnel => self.enable_full_tunnel().await?,
            TunnelMode::SplitTunnel { .. } => self.enable_split_tunnel().await?,
            TunnelMode::ProxyPac { .. } => self.enable_proxy_mode().await?,
            TunnelMode::DnsOnly => self.enable_dns_only().await?,
        }

        *self.active.write() = true;
        Ok(())
    }

    /// Disable traffic interception
    pub async fn disable(&self) -> Result<(), ClientError> {
        tracing::info!("Disabling traffic interception");
        
        #[cfg(target_os = "windows")]
        self.disable_wfp_rules()?;
        
        #[cfg(target_os = "linux")]
        self.disable_iptables_rules()?;
        
        #[cfg(target_os = "macos")]
        self.disable_pf_rules()?;

        *self.active.write() = false;
        Ok(())
    }

    /// Check if active
    pub fn is_active(&self) -> bool {
        *self.active.read()
    }

    async fn enable_full_tunnel(&self) -> Result<(), ClientError> {
        tracing::debug!("Configuring full tunnel mode");
        
        #[cfg(target_os = "windows")]
        {
            // Windows: Use WFP to redirect all traffic
            self.setup_wfp_full_tunnel()?;
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux: Use iptables/nftables
            self.setup_iptables_full_tunnel()?;
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS: Use PF rules
            self.setup_pf_full_tunnel()?;
        }
        
        Ok(())
    }

    async fn enable_split_tunnel(&self) -> Result<(), ClientError> {
        tracing::debug!("Configuring split tunnel mode");
        // Only route specified traffic through tunnel
        Ok(())
    }

    async fn enable_proxy_mode(&self) -> Result<(), ClientError> {
        tracing::debug!("Configuring proxy/PAC mode");
        // Set system proxy settings
        Ok(())
    }

    async fn enable_dns_only(&self) -> Result<(), ClientError> {
        tracing::debug!("Configuring DNS-only mode");
        // Only redirect DNS queries
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn setup_wfp_full_tunnel(&self) -> Result<(), ClientError> {
        // Windows Filtering Platform rules
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn disable_wfp_rules(&self) -> Result<(), ClientError> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn setup_iptables_full_tunnel(&self) -> Result<(), ClientError> {
        // iptables -t nat -A OUTPUT -j REDIRECT ...
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn disable_iptables_rules(&self) -> Result<(), ClientError> {
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn setup_pf_full_tunnel(&self) -> Result<(), ClientError> {
        // PF rules
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn disable_pf_rules(&self) -> Result<(), ClientError> {
        Ok(())
    }
}

impl Default for TrafficInterceptor {
    fn default() -> Self { Self::new() }
}

/// Tunnel mode
#[derive(Debug, Clone)]
pub enum TunnelMode {
    /// All traffic through SASE
    FullTunnel,
    /// Only specified traffic
    SplitTunnel {
        include: Vec<String>,
        exclude: Vec<String>,
    },
    /// Browser proxy mode
    ProxyPac {
        pac_url: String,
    },
    /// DNS only (lightweight)
    DnsOnly,
}

impl Default for TunnelMode {
    fn default() -> Self { Self::FullTunnel }
}

/// Split tunnel rules
#[derive(Debug, Clone)]
pub struct SplitTunnelRules {
    /// Apps to include (process names or paths)
    pub include_apps: Vec<String>,
    /// Apps to exclude
    pub exclude_apps: Vec<String>,
    /// Domains to include
    pub include_domains: Vec<String>,
    /// Domains to exclude
    pub exclude_domains: Vec<String>,
    /// IP ranges to include
    pub include_ips: Vec<String>,
    /// IP ranges to exclude
    pub exclude_ips: Vec<String>,
}
