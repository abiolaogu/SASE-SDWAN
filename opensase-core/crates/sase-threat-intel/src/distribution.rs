//! Intelligence Distribution
//!
//! Push threat intelligence to SASE components.

use crate::{Indicator, IocType, Confidence, Severity};
use std::collections::HashSet;

/// Distributor for pushing intelligence to SASE components
pub struct Distributor {
    /// XDP blocklist endpoint
    xdp_endpoint: Option<String>,
    /// L7 Gateway endpoint
    l7_endpoint: Option<String>,
    /// IPS engine endpoint
    ips_endpoint: Option<String>,
    /// DDoS Shield endpoint
    ddos_endpoint: Option<String>,
    /// Distribution stats
    stats: DistributorStats,
    /// Minimum confidence for distribution
    min_confidence: Confidence,
    /// HTTP client
    client: reqwest::Client,
}

#[derive(Debug, Default)]
pub struct DistributorStats {
    pub xdp_updates: std::sync::atomic::AtomicU64,
    pub l7_updates: std::sync::atomic::AtomicU64,
    pub ips_updates: std::sync::atomic::AtomicU64,
    pub ddos_updates: std::sync::atomic::AtomicU64,
    pub failed_updates: std::sync::atomic::AtomicU64,
}

/// Distribution target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionTarget {
    /// XDP first-line defense
    Xdp,
    /// L7 Gateway URL filtering
    L7Gateway,
    /// IPS engine rules
    IpsEngine,
    /// DDoS Shield
    DdosShield,
    /// All applicable targets
    All,
}

/// Distribution action
#[derive(Debug, Clone)]
pub enum DistributionAction {
    /// Add to blocklist
    Block,
    /// Remove from blocklist
    Unblock,
    /// Add to watchlist (log only)
    Watch,
    /// Update existing entry
    Update,
}

/// Distribution result
#[derive(Debug, Clone)]
pub struct DistributionResult {
    pub indicator_id: String,
    pub targets: Vec<TargetResult>,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct TargetResult {
    pub target: DistributionTarget,
    pub success: bool,
    pub error: Option<String>,
}

impl Distributor {
    pub fn new() -> Self {
        Self {
            xdp_endpoint: None,
            l7_endpoint: None,
            ips_endpoint: None,
            ddos_endpoint: None,
            stats: DistributorStats::default(),
            min_confidence: Confidence::Medium,
            client: reqwest::Client::new(),
        }
    }
    
    /// Configure XDP endpoint
    pub fn with_xdp(mut self, endpoint: &str) -> Self {
        self.xdp_endpoint = Some(endpoint.to_string());
        self
    }
    
    /// Configure L7 Gateway endpoint
    pub fn with_l7(mut self, endpoint: &str) -> Self {
        self.l7_endpoint = Some(endpoint.to_string());
        self
    }
    
    /// Configure IPS endpoint
    pub fn with_ips(mut self, endpoint: &str) -> Self {
        self.ips_endpoint = Some(endpoint.to_string());
        self
    }
    
    /// Configure DDoS Shield endpoint
    pub fn with_ddos(mut self, endpoint: &str) -> Self {
        self.ddos_endpoint = Some(endpoint.to_string());
        self
    }
    
    /// Distribute indicator to appropriate targets
    pub async fn distribute(
        &self,
        indicator: &Indicator,
        action: DistributionAction,
    ) -> DistributionResult {
        // Check confidence threshold
        if indicator.confidence < self.min_confidence {
            return DistributionResult {
                indicator_id: indicator.id.clone(),
                targets: vec![],
                success: true,
            };
        }
        
        let targets = self.get_targets_for_ioc(indicator);
        let mut results = Vec::new();
        
        for target in targets {
            let result = match target {
                DistributionTarget::Xdp => {
                    self.distribute_to_xdp(indicator, &action).await
                }
                DistributionTarget::L7Gateway => {
                    self.distribute_to_l7(indicator, &action).await
                }
                DistributionTarget::IpsEngine => {
                    self.distribute_to_ips(indicator, &action).await
                }
                DistributionTarget::DdosShield => {
                    self.distribute_to_ddos(indicator, &action).await
                }
                DistributionTarget::All => continue,
            };
            
            results.push(TargetResult {
                target,
                success: result.is_ok(),
                error: result.err(),
            });
        }
        
        let success = results.iter().all(|r| r.success);
        
        DistributionResult {
            indicator_id: indicator.id.clone(),
            targets: results,
            success,
        }
    }
    
    /// Distribute batch of indicators
    pub async fn distribute_batch(
        &self,
        indicators: &[Indicator],
        action: DistributionAction,
    ) -> Vec<DistributionResult> {
        let mut results = Vec::new();
        
        // Group by target
        let mut xdp_batch: Vec<&Indicator> = Vec::new();
        let mut l7_batch: Vec<&Indicator> = Vec::new();
        let mut ips_batch: Vec<&Indicator> = Vec::new();
        let mut ddos_batch: Vec<&Indicator> = Vec::new();
        
        for indicator in indicators {
            if indicator.confidence < self.min_confidence {
                continue;
            }
            
            let targets = self.get_targets_for_ioc(indicator);
            for target in targets {
                match target {
                    DistributionTarget::Xdp => xdp_batch.push(indicator),
                    DistributionTarget::L7Gateway => l7_batch.push(indicator),
                    DistributionTarget::IpsEngine => ips_batch.push(indicator),
                    DistributionTarget::DdosShield => ddos_batch.push(indicator),
                    DistributionTarget::All => {}
                }
            }
        }
        
        // Send batches
        if !xdp_batch.is_empty() {
            let _ = self.distribute_batch_to_xdp(&xdp_batch, &action).await;
        }
        if !l7_batch.is_empty() {
            let _ = self.distribute_batch_to_l7(&l7_batch, &action).await;
        }
        
        results
    }
    
    /// Get appropriate targets for an IoC type
    fn get_targets_for_ioc(&self, indicator: &Indicator) -> Vec<DistributionTarget> {
        let mut targets = Vec::new();
        
        match indicator.ioc_type {
            IocType::IPv4 | IocType::IPv6 | IocType::Cidr => {
                if self.xdp_endpoint.is_some() {
                    targets.push(DistributionTarget::Xdp);
                }
                if self.ddos_endpoint.is_some() && indicator.severity >= Severity::High {
                    targets.push(DistributionTarget::DdosShield);
                }
            }
            IocType::Domain | IocType::Url => {
                if self.l7_endpoint.is_some() {
                    targets.push(DistributionTarget::L7Gateway);
                }
            }
            IocType::FileHashMd5 | IocType::FileHashSha1 | IocType::FileHashSha256 => {
                if self.ips_endpoint.is_some() {
                    targets.push(DistributionTarget::IpsEngine);
                }
            }
            IocType::JarmHash | IocType::Ja3Hash | IocType::SslCertHash => {
                if self.l7_endpoint.is_some() {
                    targets.push(DistributionTarget::L7Gateway);
                }
            }
            _ => {}
        }
        
        targets
    }
    
    async fn distribute_to_xdp(&self, indicator: &Indicator, action: &DistributionAction) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        
        let endpoint = self.xdp_endpoint.as_ref()
            .ok_or("XDP endpoint not configured")?;
        
        let payload = serde_json::json!({
            "action": match action {
                DistributionAction::Block => "block",
                DistributionAction::Unblock => "unblock",
                DistributionAction::Watch => "watch",
                DistributionAction::Update => "update",
            },
            "type": format!("{:?}", indicator.ioc_type),
            "value": indicator.value,
            "ttl": 3600,
        });
        
        let response = self.client.post(format!("{}/blocklist", endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            self.stats.xdp_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.failed_updates.fetch_add(1, Ordering::Relaxed);
            Err(format!("XDP update failed: {}", response.status()))
        }
    }
    
    async fn distribute_to_l7(&self, indicator: &Indicator, action: &DistributionAction) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        
        let endpoint = self.l7_endpoint.as_ref()
            .ok_or("L7 endpoint not configured")?;
        
        let category = match indicator.context.threat_type {
            Some(crate::ThreatType::Phishing) => "phishing",
            Some(crate::ThreatType::Malware) => "malware",
            Some(crate::ThreatType::C2) => "c2",
            _ => "threat",
        };
        
        let payload = serde_json::json!({
            "action": match action {
                DistributionAction::Block => "block",
                DistributionAction::Unblock => "unblock",
                DistributionAction::Watch => "log",
                DistributionAction::Update => "update",
            },
            "type": format!("{:?}", indicator.ioc_type),
            "value": indicator.value,
            "category": category,
        });
        
        let response = self.client.post(format!("{}/url-filter", endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            self.stats.l7_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.failed_updates.fetch_add(1, Ordering::Relaxed);
            Err(format!("L7 update failed: {}", response.status()))
        }
    }
    
    async fn distribute_to_ips(&self, indicator: &Indicator, action: &DistributionAction) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        
        let endpoint = self.ips_endpoint.as_ref()
            .ok_or("IPS endpoint not configured")?;
        
        let payload = serde_json::json!({
            "action": match action {
                DistributionAction::Block => "alert",
                DistributionAction::Unblock => "remove",
                DistributionAction::Watch => "log",
                DistributionAction::Update => "update",
            },
            "type": "file_hash",
            "hash": indicator.value,
            "hash_type": format!("{:?}", indicator.ioc_type),
        });
        
        let response = self.client.post(format!("{}/rules", endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            self.stats.ips_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.failed_updates.fetch_add(1, Ordering::Relaxed);
            Err(format!("IPS update failed: {}", response.status()))
        }
    }
    
    async fn distribute_to_ddos(&self, indicator: &Indicator, action: &DistributionAction) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        
        let endpoint = self.ddos_endpoint.as_ref()
            .ok_or("DDoS endpoint not configured")?;
        
        let payload = serde_json::json!({
            "action": match action {
                DistributionAction::Block => "block",
                DistributionAction::Unblock => "unblock",
                _ => "block",
            },
            "ip": indicator.value,
            "reason": "threat_intel",
        });
        
        let response = self.client.post(format!("{}/blocklist", endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            self.stats.ddos_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.failed_updates.fetch_add(1, Ordering::Relaxed);
            Err(format!("DDoS update failed: {}", response.status()))
        }
    }
    
    async fn distribute_batch_to_xdp(&self, indicators: &[&Indicator], action: &DistributionAction) -> Result<(), String> {
        let endpoint = self.xdp_endpoint.as_ref()
            .ok_or("XDP endpoint not configured")?;
        
        let items: Vec<_> = indicators.iter().map(|i| {
            serde_json::json!({
                "type": format!("{:?}", i.ioc_type),
                "value": i.value,
            })
        }).collect();
        
        let payload = serde_json::json!({
            "action": match action {
                DistributionAction::Block => "block",
                DistributionAction::Unblock => "unblock",
                _ => "block",
            },
            "items": items,
        });
        
        let response = self.client.post(format!("{}/blocklist/batch", endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Batch XDP update failed: {}", response.status()))
        }
    }
    
    async fn distribute_batch_to_l7(&self, indicators: &[&Indicator], action: &DistributionAction) -> Result<(), String> {
        let endpoint = self.l7_endpoint.as_ref()
            .ok_or("L7 endpoint not configured")?;
        
        let items: Vec<_> = indicators.iter().map(|i| {
            serde_json::json!({
                "type": format!("{:?}", i.ioc_type),
                "value": i.value,
            })
        }).collect();
        
        let payload = serde_json::json!({
            "action": match action {
                DistributionAction::Block => "block",
                _ => "block",
            },
            "items": items,
        });
        
        let response = self.client.post(format!("{}/url-filter/batch", endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Batch L7 update failed: {}", response.status()))
        }
    }
    
    /// Get distribution statistics
    pub fn get_stats(&self) -> DistributorSnapshot {
        use std::sync::atomic::Ordering;
        
        DistributorSnapshot {
            xdp_updates: self.stats.xdp_updates.load(Ordering::Relaxed),
            l7_updates: self.stats.l7_updates.load(Ordering::Relaxed),
            ips_updates: self.stats.ips_updates.load(Ordering::Relaxed),
            ddos_updates: self.stats.ddos_updates.load(Ordering::Relaxed),
            failed_updates: self.stats.failed_updates.load(Ordering::Relaxed),
        }
    }
}

impl Default for Distributor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DistributorSnapshot {
    pub xdp_updates: u64,
    pub l7_updates: u64,
    pub ips_updates: u64,
    pub ddos_updates: u64,
    pub failed_updates: u64,
}
