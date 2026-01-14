//! Main Orchestrator

use crate::pop::{PopDefinition, PopInstance, PopStatus};
use crate::terraform::{TerraformGenerator, TerraformOutput};
use crate::health::{HealthMonitor, HealthEndpoint, CheckType};
use crate::anycast::{AnycastRouter, AnycastRoute};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Global PoP Orchestrator
pub struct Orchestrator {
    /// Active PoPs
    pops: Arc<RwLock<HashMap<String, PopInstance>>>,
    /// Terraform generator
    terraform: TerraformGenerator,
    /// Health monitor
    health: Arc<HealthMonitor>,
    /// Anycast router
    anycast: Arc<AnycastRouter>,
    /// Configuration
    config: OrchestratorConfig,
}

impl Orchestrator {
    /// Create new orchestrator
    pub fn new(config: OrchestratorConfig) -> Self {
        let health = Arc::new(HealthMonitor::new());
        let anycast = Arc::new(AnycastRouter::new(health.clone(), config.bgp_asn));
        
        Self {
            pops: Arc::new(RwLock::new(HashMap::new())),
            terraform: TerraformGenerator::new(),
            health,
            anycast,
            config,
        }
    }

    /// Deploy new PoP
    pub async fn deploy(&self, definition: PopDefinition) -> Result<PopInstance, OrchestratorError> {
        // Validate
        definition.validate()?;

        // Generate Terraform
        let tf = self.terraform.generate(&definition)?;
        
        // Write Terraform files
        let tf_dir = std::path::PathBuf::from(&self.config.terraform_dir)
            .join(&definition.pop_id);
        tf.write_to_dir(&tf_dir)?;

        // Create instance record
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let instance = PopInstance {
            definition: definition.clone(),
            status: PopStatus::Provisioning,
            public_ips: Vec::new(),
            private_ips: Vec::new(),
            created_at: now,
            updated_at: now,
            health_score: 0.0,
        };

        // Register for health monitoring
        self.health.register(
            &definition.pop_id,
            vec![HealthEndpoint {
                url: format!("http://{}/health", &definition.pop_id),
                check_type: CheckType::Http,
                timeout_ms: 5000,
            }],
        );

        // Add to anycast if enabled
        if let Some(ref anycast_ip) = definition.network.anycast_ip {
            self.anycast.add_route(
                anycast_ip,
                AnycastRoute::new(&definition.pop_id, 100)
                    .with_coords(definition.region.latitude, definition.region.longitude),
            );
        }

        // Store
        self.pops.write().insert(definition.pop_id.clone(), instance.clone());

        Ok(instance)
    }

    /// Terminate PoP
    pub async fn terminate(&self, pop_id: &str) -> Result<(), OrchestratorError> {
        let mut pops = self.pops.write();
        
        if let Some(pop) = pops.get_mut(pop_id) {
            pop.status = PopStatus::Terminated;
            
            // Remove from anycast
            self.anycast.remove_pop(pop_id);
            
            // Terraform destroy would go here
            Ok(())
        } else {
            Err(OrchestratorError::PopNotFound(pop_id.to_string()))
        }
    }

    /// Get PoP status
    pub fn get_pop(&self, pop_id: &str) -> Option<PopInstance> {
        self.pops.read().get(pop_id).cloned()
    }

    /// List all PoPs
    pub fn list_pops(&self) -> Vec<PopInstance> {
        self.pops.read().values().cloned().collect()
    }

    /// Get PoPs by status
    pub fn get_by_status(&self, status: PopStatus) -> Vec<PopInstance> {
        self.pops.read()
            .values()
            .filter(|p| p.status == status)
            .cloned()
            .collect()
    }

    /// Get healthy PoP count
    pub fn healthy_count(&self) -> usize {
        self.pops.read()
            .values()
            .filter(|p| p.status == PopStatus::Running && p.health_score > 0.8)
            .count()
    }

    /// Get total PoP count
    pub fn total_count(&self) -> usize {
        self.pops.read().len()
    }

    /// Scale PoP (change instance count)
    pub async fn scale(&self, pop_id: &str, instance_count: u32) -> Result<(), OrchestratorError> {
        let mut pops = self.pops.write();
        
        if let Some(pop) = pops.get_mut(pop_id) {
            pop.definition.capacity.instance_count = instance_count;
            pop.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // Regenerate Terraform would go here
            Ok(())
        } else {
            Err(OrchestratorError::PopNotFound(pop_id.to_string()))
        }
    }

    /// Get anycast router
    pub fn anycast(&self) -> Arc<AnycastRouter> {
        self.anycast.clone()
    }

    /// Get health monitor
    pub fn health(&self) -> Arc<HealthMonitor> {
        self.health.clone()
    }
}

/// Orchestrator configuration
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    pub terraform_dir: String,
    pub bgp_asn: u32,
    pub default_anycast_ip: Option<String>,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            terraform_dir: "./terraform".to_string(),
            bgp_asn: 65000,
            default_anycast_ip: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("PoP not found: {0}")]
    PopNotFound(String),
    #[error("validation error: {0}")]
    Validation(#[from] crate::pop::ValidationError),
    #[error("terraform error: {0}")]
    Terraform(#[from] crate::terraform::GeneratorError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pop::{Region, Continent, PopTier, CapacitySpec, ServiceConfig, ResourceLimits, PortMapping};
    use crate::provider::CloudProvider;

    #[tokio::test]
    async fn test_orchestrator_deploy() {
        let config = OrchestratorConfig {
            terraform_dir: "/tmp/opensase-tf".into(),
            ..Default::default()
        };
        let orch = Orchestrator::new(config);

        let region = Region::new("us-east-1", "US East", Continent::NorthAmerica, 39.0, -77.0);
        let pop = PopDefinition::new("test-pop", region, CloudProvider::Aws, PopTier::Edge)
            .with_capacity(CapacitySpec::small())
            .with_service(ServiceConfig {
                name: "tunnel".into(),
                image: "opensase/tunnel:latest".into(),
                ports: vec![PortMapping { container_port: 443, host_port: 443, protocol: "tcp".into() }],
                env: vec![],
                resources: ResourceLimits::default(),
                health_check: None,
            });

        let result = orch.deploy(pop).await;
        assert!(result.is_ok());
        assert_eq!(orch.total_count(), 1);
    }
}
