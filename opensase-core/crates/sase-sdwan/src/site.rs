//! Site Management Module
//!
//! Multi-site orchestration for SD-WAN.

use crate::{Result, SdwanError};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// Site status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteStatus {
    /// Site is pending configuration
    Pending,
    /// Site is being provisioned
    Provisioning,
    /// Site is online and healthy
    Online,
    /// Site is degraded (partial connectivity)
    Degraded,
    /// Site is offline
    Offline,
    /// Site has errors
    Error,
}

/// Geographic location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub city: String,
    pub country: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

/// WAN link configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanLink {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub link_type: WanLinkType,
    pub bandwidth_mbps: u32,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
    pub metric: u32,
    pub enabled: bool,
    pub status: LinkStatus,
}

/// WAN link type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WanLinkType {
    Mpls,
    Internet,
    Lte,
    Satellite,
    DedicatedLine,
}

/// Link status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkStatus {
    Up,
    Down,
    Degraded,
    Unknown,
}

/// Network segment (VRF)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub vlan: Option<u16>,
    pub color: Option<String>,
}

/// Edge device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub status: DeviceStatus,
    pub wan_links: Vec<String>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Device status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Pending,
    Approved,
    Online,
    Offline,
    Error,
}

/// Site configuration for creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteConfig {
    pub name: String,
    pub description: Option<String>,
    pub location: Location,
    pub site_type: SiteType,
    pub wan_links: Vec<WanLinkConfig>,
    pub segments: Vec<String>,
}

/// Site type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteType {
    /// Hub site (PoP/datacenter)
    Hub,
    /// Branch office
    Branch,
    /// Remote worker
    Remote,
}

/// WAN link configuration for creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanLinkConfig {
    pub name: String,
    pub interface: String,
    pub link_type: WanLinkType,
    pub bandwidth_mbps: u32,
    pub dhcp: bool,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
    pub metric: u32,
}

/// Site
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub location: Location,
    pub site_type: SiteType,
    pub devices: Vec<Device>,
    pub wan_links: Vec<WanLink>,
    pub segments: Vec<Segment>,
    pub status: SiteStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Site {
    /// Create new site from config
    pub fn new(config: SiteConfig) -> Self {
        let now = Utc::now();
        
        let wan_links: Vec<WanLink> = config.wan_links.iter().enumerate()
            .map(|(i, wl)| WanLink {
                id: format!("wl-{}", i + 1),
                name: wl.name.clone(),
                interface: wl.interface.clone(),
                link_type: wl.link_type,
                bandwidth_mbps: wl.bandwidth_mbps,
                ip_address: wl.ip_address.clone(),
                gateway: wl.gateway.clone(),
                metric: wl.metric,
                enabled: true,
                status: LinkStatus::Unknown,
            })
            .collect();
        
        Self {
            id: Uuid::new_v4().to_string(),
            name: config.name,
            description: config.description,
            location: config.location,
            site_type: config.site_type,
            devices: Vec::new(),
            wan_links,
            segments: Vec::new(),
            status: SiteStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }
    
    /// Check if site is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, SiteStatus::Online)
    }
    
    /// Get primary WAN link
    pub fn primary_wan(&self) -> Option<&WanLink> {
        self.wan_links.iter()
            .filter(|w| w.enabled && w.status == LinkStatus::Up)
            .min_by_key(|w| w.metric)
    }
    
    /// Get available WAN links
    pub fn available_wans(&self) -> Vec<&WanLink> {
        self.wan_links.iter()
            .filter(|w| w.enabled && w.status == LinkStatus::Up)
            .collect()
    }
}

/// Site Manager
pub struct SiteManager {
    sites: DashMap<String, Site>,
    segments: DashMap<String, Segment>,
}

impl SiteManager {
    /// Create new site manager
    pub fn new() -> Self {
        Self {
            sites: DashMap::new(),
            segments: DashMap::new(),
        }
    }
    
    /// Create a new site
    pub async fn create_site(&self, config: SiteConfig) -> Result<Site> {
        let site = Site::new(config);
        let site_id = site.id.clone();
        
        info!("Creating site: {} ({})", site.name, site_id);
        self.sites.insert(site_id.clone(), site.clone());
        
        Ok(site)
    }
    
    /// Get site by ID
    pub fn get_site(&self, id: &str) -> Option<Site> {
        self.sites.get(id).map(|s| s.clone())
    }
    
    /// Get all sites
    pub fn list_sites(&self) -> Vec<Site> {
        self.sites.iter().map(|s| s.clone()).collect()
    }
    
    /// Update site status
    pub async fn update_site_status(&self, id: &str, status: SiteStatus) -> Result<()> {
        if let Some(mut site) = self.sites.get_mut(id) {
            site.status = status;
            site.updated_at = Utc::now();
            info!("Site {} status updated to {:?}", id, status);
            Ok(())
        } else {
            Err(SdwanError::SiteNotFound(id.to_string()))
        }
    }
    
    /// Add device to site
    pub async fn add_device(&self, site_id: &str, device: Device) -> Result<()> {
        if let Some(mut site) = self.sites.get_mut(site_id) {
            info!("Adding device {} to site {}", device.name, site_id);
            site.devices.push(device);
            site.updated_at = Utc::now();
            Ok(())
        } else {
            Err(SdwanError::SiteNotFound(site_id.to_string()))
        }
    }
    
    /// Update WAN link status
    pub async fn update_wan_status(
        &self,
        site_id: &str,
        wan_id: &str,
        status: LinkStatus,
    ) -> Result<()> {
        if let Some(mut site) = self.sites.get_mut(site_id) {
            if let Some(wan) = site.wan_links.iter_mut().find(|w| w.id == wan_id) {
                wan.status = status;
                info!("WAN {} on site {} status: {:?}", wan_id, site_id, status);
            }
            site.updated_at = Utc::now();
            
            // Update site status based on WAN health
            let up_wans = site.wan_links.iter().filter(|w| w.status == LinkStatus::Up).count();
            site.status = match up_wans {
                0 => SiteStatus::Offline,
                n if n < site.wan_links.len() => SiteStatus::Degraded,
                _ => SiteStatus::Online,
            };
            
            Ok(())
        } else {
            Err(SdwanError::SiteNotFound(site_id.to_string()))
        }
    }
    
    /// Create segment
    pub async fn create_segment(&self, segment: Segment) -> Result<()> {
        info!("Creating segment: {} (ID: {})", segment.name, segment.id);
        self.segments.insert(segment.name.clone(), segment);
        Ok(())
    }
    
    /// Get all segments
    pub fn list_segments(&self) -> Vec<Segment> {
        self.segments.iter().map(|s| s.clone()).collect()
    }
    
    /// Get sites by status
    pub fn get_sites_by_status(&self, status: SiteStatus) -> Vec<Site> {
        self.sites.iter()
            .filter(|s| s.status == status)
            .map(|s| s.clone())
            .collect()
    }
    
    /// Get site count
    pub fn site_count(&self) -> usize {
        self.sites.len()
    }
}

impl Default for SiteManager {
    fn default() -> Self {
        Self::new()
    }
}
