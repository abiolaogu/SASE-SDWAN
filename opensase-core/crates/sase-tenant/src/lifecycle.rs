//! Tenant Lifecycle Management

use crate::model::{Tenant, TenantId, TenantTier, TenantStatus, TenantMetadata};
use crate::isolation::IsolationEngine;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Tenant registry
pub struct TenantRegistry {
    /// All tenants
    tenants: Arc<RwLock<HashMap<TenantId, Tenant>>>,
    /// Isolation engine
    isolation: Arc<IsolationEngine>,
}

impl TenantRegistry {
    pub fn new(isolation: Arc<IsolationEngine>) -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            isolation,
        }
    }

    /// Create new tenant
    pub fn create(&self, name: &str, tier: TenantTier) -> Result<Tenant, LifecycleError> {
        let tenant = Tenant::new(name, tier);
        
        // Create VRF
        self.isolation.create_vrf(tenant.tenant_id, crate::isolation::VrfConfig {
            overlay_cidr: tenant.network_config.overlay_network.clone(),
            nat_cidr: "100.64.0.0/10".into(),
            max_flows: tenant.limits.max_connections as usize,
        })?;

        self.tenants.write().insert(tenant.tenant_id, tenant.clone());
        
        Ok(tenant)
    }

    /// Get tenant
    pub fn get(&self, tenant_id: &TenantId) -> Option<Tenant> {
        self.tenants.read().get(tenant_id).cloned()
    }

    /// List all tenants
    pub fn list(&self) -> Vec<Tenant> {
        self.tenants.read().values().cloned().collect()
    }

    /// Update tenant
    pub fn update(&self, tenant_id: &TenantId, update: TenantUpdate) -> Result<Tenant, LifecycleError> {
        let mut tenants = self.tenants.write();
        let tenant = tenants.get_mut(tenant_id)
            .ok_or(LifecycleError::NotFound)?;

        if let Some(name) = update.name {
            tenant.name = name;
        }
        if let Some(tier) = update.tier {
            tenant.tier = tier;
            tenant.limits = crate::model::ResourceLimits::for_tier(tier);
        }
        
        tenant.metadata.updated_at = now();
        
        Ok(tenant.clone())
    }

    /// Suspend tenant
    pub fn suspend(&self, tenant_id: &TenantId) -> Result<(), LifecycleError> {
        let mut tenants = self.tenants.write();
        let tenant = tenants.get_mut(tenant_id)
            .ok_or(LifecycleError::NotFound)?;
        
        tenant.metadata.status = TenantStatus::Suspended;
        tenant.metadata.updated_at = now();
        
        Ok(())
    }

    /// Begin offboarding
    pub fn offboard(&self, tenant_id: &TenantId) -> Result<OffboardingState, LifecycleError> {
        let mut tenants = self.tenants.write();
        let tenant = tenants.get_mut(tenant_id)
            .ok_or(LifecycleError::NotFound)?;
        
        tenant.metadata.status = TenantStatus::Offboarding;
        
        Ok(OffboardingState {
            tenant_id: *tenant_id,
            stage: OffboardingStage::NotifyUsers,
            started_at: now(),
        })
    }

    /// Delete tenant (after offboarding)
    pub fn delete(&self, tenant_id: &TenantId) -> Result<(), LifecycleError> {
        // Remove VRF
        self.isolation.delete_vrf(tenant_id);
        
        // Remove from registry
        self.tenants.write().remove(tenant_id);
        
        Ok(())
    }

    /// Get tenant count
    pub fn count(&self) -> usize {
        self.tenants.read().len()
    }
}

/// Tenant update request
#[derive(Debug, Clone, Default)]
pub struct TenantUpdate {
    pub name: Option<String>,
    pub tier: Option<TenantTier>,
}

/// Offboarding state
#[derive(Debug, Clone)]
pub struct OffboardingState {
    pub tenant_id: TenantId,
    pub stage: OffboardingStage,
    pub started_at: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum OffboardingStage {
    NotifyUsers,
    ExportData,
    DisableAccess,
    CryptoErase,
    Complete,
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("tenant not found")]
    NotFound,
    #[error("isolation error: {0}")]
    Isolation(#[from] crate::isolation::IsolationError),
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_lifecycle() {
        let isolation = Arc::new(IsolationEngine::new());
        let registry = TenantRegistry::new(isolation);
        
        // Create
        let tenant = registry.create("TestCorp", TenantTier::Pro).unwrap();
        assert_eq!(registry.count(), 1);
        
        // Update
        let updated = registry.update(&tenant.tenant_id, TenantUpdate {
            name: Some("TestCorp Inc".into()),
            tier: Some(TenantTier::Enterprise),
        }).unwrap();
        assert_eq!(updated.tier, TenantTier::Enterprise);
        
        // Suspend
        registry.suspend(&tenant.tenant_id).unwrap();
        let suspended = registry.get(&tenant.tenant_id).unwrap();
        assert_eq!(suspended.metadata.status, TenantStatus::Suspended);
        
        // Delete
        registry.delete(&tenant.tenant_id).unwrap();
        assert_eq!(registry.count(), 0);
    }
}
