//! Fine-grained Permissions

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Permission enum for fine-grained access control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // Sites
    SitesRead,
    SitesWrite,
    SitesDelete,
    
    // Users
    UsersRead,
    UsersWrite,
    UsersDelete,
    
    // Policies
    PoliciesRead,
    PoliciesWrite,
    PoliciesDelete,
    
    // Apps
    AppsRead,
    AppsWrite,
    
    // Alerts
    AlertsRead,
    AlertsAcknowledge,
    AlertsResolve,
    
    // Analytics
    AnalyticsRead,
    
    // Tunnels
    TunnelsRead,
    TunnelsWrite,
    
    // Webhooks
    WebhooksRead,
    WebhooksWrite,
    
    // API Keys
    ApiKeysRead,
    ApiKeysWrite,
    
    // Admin
    Admin,
}

impl Permission {
    /// Get all permissions for a role
    pub fn for_role(role: &str) -> HashSet<Permission> {
        match role {
            "admin" => Self::all(),
            "editor" => Self::editor(),
            "viewer" => Self::viewer(),
            "analyst" => Self::analyst(),
            _ => HashSet::new(),
        }
    }

    fn all() -> HashSet<Permission> {
        use Permission::*;
        [
            SitesRead, SitesWrite, SitesDelete,
            UsersRead, UsersWrite, UsersDelete,
            PoliciesRead, PoliciesWrite, PoliciesDelete,
            AppsRead, AppsWrite,
            AlertsRead, AlertsAcknowledge, AlertsResolve,
            AnalyticsRead,
            TunnelsRead, TunnelsWrite,
            WebhooksRead, WebhooksWrite,
            ApiKeysRead, ApiKeysWrite,
            Admin,
        ].into_iter().collect()
    }

    fn editor() -> HashSet<Permission> {
        use Permission::*;
        [
            SitesRead, SitesWrite,
            UsersRead,
            PoliciesRead, PoliciesWrite,
            AppsRead, AppsWrite,
            AlertsRead, AlertsAcknowledge, AlertsResolve,
            AnalyticsRead,
            TunnelsRead,
        ].into_iter().collect()
    }

    fn viewer() -> HashSet<Permission> {
        use Permission::*;
        [
            SitesRead, UsersRead, PoliciesRead,
            AppsRead, AlertsRead, AnalyticsRead, TunnelsRead,
        ].into_iter().collect()
    }

    fn analyst() -> HashSet<Permission> {
        use Permission::*;
        [
            SitesRead, PoliciesRead, AppsRead,
            AlertsRead, AlertsAcknowledge, AlertsResolve,
            AnalyticsRead, TunnelsRead,
        ].into_iter().collect()
    }
}

/// Check if a set of permissions allows an action
pub fn has_permission(permissions: &HashSet<Permission>, required: Permission) -> bool {
    permissions.contains(&Permission::Admin) || permissions.contains(&required)
}

/// Parse permissions from scope strings (e.g., "sites:read", "users:write")
pub fn parse_scopes(scopes: &[String]) -> HashSet<Permission> {
    scopes.iter().filter_map(|s| {
        match s.as_str() {
            "sites:read" => Some(Permission::SitesRead),
            "sites:write" => Some(Permission::SitesWrite),
            "users:read" => Some(Permission::UsersRead),
            "users:write" => Some(Permission::UsersWrite),
            "policies:read" => Some(Permission::PoliciesRead),
            "policies:write" => Some(Permission::PoliciesWrite),
            "alerts:read" => Some(Permission::AlertsRead),
            "alerts:ack" => Some(Permission::AlertsAcknowledge),
            "analytics:read" => Some(Permission::AnalyticsRead),
            "admin" => Some(Permission::Admin),
            "read:all" => Some(Permission::SitesRead), // Expand as needed
            _ => None,
        }
    }).collect()
}
