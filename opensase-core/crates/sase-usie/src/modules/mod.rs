//! Security Inspection Modules

pub mod firewall;
pub mod ips;
pub mod url_filter;
pub mod dns_security;
pub mod dlp;
pub mod antimalware;

use crate::context::{InspectionContext, ModuleVerdict};

/// Security module trait
pub trait SecurityModule: Send + Sync {
    /// Module name
    fn name(&self) -> &'static str;
    
    /// Inspect packet and return verdict
    fn inspect(&self, ctx: &InspectionContext) -> Option<ModuleVerdict>;
    
    /// Check if module is enabled
    fn is_enabled(&self) -> bool { true }
}
