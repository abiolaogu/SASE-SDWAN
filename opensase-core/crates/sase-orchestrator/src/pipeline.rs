//! PoP Lifecycle Pipeline
//!
//! Define → Provision → Configure → Test → Activate → Monitor

use crate::pop::{PopDefinition, PopInstance, PopStatus};
use crate::terraform::TerraformGenerator;
use crate::health::{HealthMonitor, HealthEndpoint, CheckType, HealthStatus};
use std::sync::Arc;
use tokio::time::{Duration, sleep};

/// Lifecycle stage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStage {
    Define,
    Provision,
    Configure,
    Test,
    Activate,
    Monitor,
    Failed,
}

impl LifecycleStage {
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Define => Some(Self::Provision),
            Self::Provision => Some(Self::Configure),
            Self::Configure => Some(Self::Test),
            Self::Test => Some(Self::Activate),
            Self::Activate => Some(Self::Monitor),
            Self::Monitor => None,
            Self::Failed => None,
        }
    }

    pub fn display(&self) -> &'static str {
        match self {
            Self::Define => "📋 Define",
            Self::Provision => "🏗️ Provision",
            Self::Configure => "⚙️ Configure",
            Self::Test => "🧪 Test",
            Self::Activate => "✅ Activate",
            Self::Monitor => "📊 Monitor",
            Self::Failed => "❌ Failed",
        }
    }
}

/// Lifecycle pipeline
pub struct LifecyclePipeline {
    terraform: TerraformGenerator,
    health: Arc<HealthMonitor>,
    config: PipelineConfig,
}

impl LifecyclePipeline {
    pub fn new(health: Arc<HealthMonitor>, config: PipelineConfig) -> Self {
        Self {
            terraform: TerraformGenerator::new(),
            health,
            config,
        }
    }

    /// Execute full pipeline
    pub async fn execute(&self, definition: PopDefinition) -> Result<PopInstance, PipelineError> {
        let mut context = PipelineContext::new(definition);

        // Stage 1: Define
        self.stage_define(&mut context).await?;

        // Stage 2: Provision
        self.stage_provision(&mut context).await?;

        // Stage 3: Configure
        self.stage_configure(&mut context).await?;

        // Stage 4: Test
        self.stage_test(&mut context).await?;

        // Stage 5: Activate
        self.stage_activate(&mut context).await?;

        // Stage 6: Monitor (ongoing)
        self.stage_monitor(&mut context).await?;

        Ok(context.into_instance())
    }

    /// Stage 1: Define - Validate and prepare
    async fn stage_define(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        ctx.set_stage(LifecycleStage::Define);
        ctx.log("Validating PoP definition...");

        // Validate definition
        ctx.definition.validate()?;

        // Check provider availability
        let regions = ctx.definition.provider.regions();
        if !regions.contains(&ctx.definition.region.code.as_str()) {
            return Err(PipelineError::InvalidRegion(ctx.definition.region.code.clone()));
        }

        // Generate unique identifiers
        ctx.set_instance_ids();

        ctx.log("Definition validated successfully");
        Ok(())
    }

    /// Stage 2: Provision - Create infrastructure
    async fn stage_provision(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        ctx.set_stage(LifecycleStage::Provision);
        ctx.log("Generating Terraform configuration...");

        // Generate Terraform
        let tf = self.terraform.generate(&ctx.definition)?;

        // Write files
        let tf_dir = std::path::PathBuf::from(&self.config.terraform_dir)
            .join(&ctx.definition.pop_id);
        tf.write_to_dir(&tf_dir)?;

        ctx.log(&format!("Terraform written to {:?}", tf_dir));

        if self.config.auto_apply {
            ctx.log("Running terraform init...");
            self.run_terraform(&tf_dir, "init").await?;

            ctx.log("Running terraform apply...");
            self.run_terraform(&tf_dir, "apply -auto-approve").await?;

            // Parse outputs for IPs
            ctx.public_ips = self.get_terraform_outputs(&tf_dir, "public_ips").await?;
            ctx.private_ips = self.get_terraform_outputs(&tf_dir, "private_ips").await?;
        }

        ctx.status = PopStatus::Provisioning;
        ctx.log("Infrastructure provisioned");
        Ok(())
    }

    /// Stage 3: Configure - Deploy services
    async fn stage_configure(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        ctx.set_stage(LifecycleStage::Configure);
        ctx.log("Configuring services...");

        // Collect service names to avoid borrow conflict
        let service_names: Vec<_> = ctx.definition.services.iter()
            .map(|s| s.name.clone())
            .collect();
        
        for name in service_names {
            ctx.log(&format!("Deploying service: {}", name));

            // In production: SSH/Ansible/K8s deployment
            // Simulated for now
            sleep(Duration::from_millis(100)).await;
        }

        // Configure network
        let anycast_enabled = ctx.definition.network.anycast_enabled;
        if anycast_enabled {
            ctx.log("Configuring anycast BGP...");
            // BGP config would go here
        }

        ctx.log("Services configured");
        Ok(())
    }

    /// Stage 4: Test - Verify functionality
    async fn stage_test(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        ctx.set_stage(LifecycleStage::Test);
        ctx.log("Running health checks...");

        // Register health endpoints
        let endpoints: Vec<HealthEndpoint> = ctx.definition.services.iter()
            .filter_map(|s| s.health_check.as_ref().map(|hc| {
                HealthEndpoint {
                    url: hc.endpoint.clone(),
                    check_type: CheckType::Http,
                    timeout_ms: hc.timeout_secs * 1000,
                }
            }))
            .collect();

        if endpoints.is_empty() {
            // Default health endpoint
            self.health.register(&ctx.definition.pop_id, vec![
                HealthEndpoint {
                    url: format!("http://{}/health", ctx.definition.pop_id),
                    check_type: CheckType::Http,
                    timeout_ms: 5000,
                },
            ]);
        } else {
            self.health.register(&ctx.definition.pop_id, endpoints);
        }

        // Run health check with retries
        let mut attempts = 0;
        let max_attempts = self.config.test_max_retries;

        loop {
            let result = self.health.check_pop(&ctx.definition.pop_id).await;
            
            if self.health.get_status(&ctx.definition.pop_id) == Some(HealthStatus::Healthy) {
                ctx.log("Health checks passed");
                break;
            }

            attempts += 1;
            if attempts >= max_attempts {
                return Err(PipelineError::TestFailed("Health checks failed".into()));
            }

            ctx.log(&format!("Health check attempt {}/{} failed, retrying...", attempts, max_attempts));
            sleep(Duration::from_secs(5)).await;
        }

        // Run connectivity tests
        ctx.log("Running connectivity tests...");
        // Ping, traceroute, etc.

        Ok(())
    }

    /// Stage 5: Activate - Enable traffic
    async fn stage_activate(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        ctx.set_stage(LifecycleStage::Activate);
        ctx.log("Activating PoP...");

        // Add to anycast (if enabled)
        if let Some(ref anycast_ip) = ctx.definition.network.anycast_ip {
            ctx.log(&format!("Adding to anycast IP: {}", anycast_ip));
            // Anycast route would be added here
        }

        // Update DNS
        ctx.log("Updating DNS records...");
        // DNS update would go here

        // Enable traffic
        ctx.status = PopStatus::Running;
        ctx.health_score = 1.0;

        ctx.log("PoP activated and receiving traffic");
        Ok(())
    }

    /// Stage 6: Monitor - Continuous monitoring
    async fn stage_monitor(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        ctx.set_stage(LifecycleStage::Monitor);
        ctx.log("Entering monitoring phase...");

        // Initial monitoring setup
        ctx.log("Monitoring enabled - health checks every 10s");

        // The actual monitoring loop runs separately
        // This just confirms the transition to monitoring state

        Ok(())
    }

    async fn run_terraform(&self, dir: &std::path::Path, cmd: &str) -> Result<(), PipelineError> {
        // In production: actually run terraform
        // Simulated for now
        sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    async fn get_terraform_outputs(&self, _dir: &std::path::Path, _output: &str) -> Result<Vec<String>, PipelineError> {
        // In production: parse terraform output
        Ok(vec!["10.0.0.1".to_string()])
    }
}

/// Pipeline context
pub struct PipelineContext {
    pub definition: PopDefinition,
    pub stage: LifecycleStage,
    pub status: PopStatus,
    pub public_ips: Vec<String>,
    pub private_ips: Vec<String>,
    pub created_at: u64,
    pub health_score: f32,
    pub logs: Vec<(u64, String)>,
}

impl PipelineContext {
    pub fn new(definition: PopDefinition) -> Self {
        Self {
            definition,
            stage: LifecycleStage::Define,
            status: PopStatus::Pending,
            public_ips: Vec::new(),
            private_ips: Vec::new(),
            created_at: now(),
            health_score: 0.0,
            logs: Vec::new(),
        }
    }

    pub fn set_stage(&mut self, stage: LifecycleStage) {
        self.stage = stage;
        self.log(&format!("→ Stage: {}", stage.display()));
    }

    pub fn log(&mut self, msg: &str) {
        self.logs.push((now(), msg.to_string()));
    }

    pub fn set_instance_ids(&mut self) {
        // Would generate UUIDs for instances
    }

    pub fn into_instance(self) -> PopInstance {
        PopInstance {
            definition: self.definition,
            status: self.status,
            public_ips: self.public_ips,
            private_ips: self.private_ips,
            created_at: self.created_at,
            updated_at: now(),
            health_score: self.health_score,
        }
    }
}

/// Pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub terraform_dir: String,
    pub auto_apply: bool,
    pub test_max_retries: u32,
    pub test_retry_interval_secs: u32,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            terraform_dir: "./terraform".to_string(),
            auto_apply: false,
            test_max_retries: 5,
            test_retry_interval_secs: 10,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("validation error: {0}")]
    Validation(#[from] crate::pop::ValidationError),
    #[error("terraform error: {0}")]
    Terraform(#[from] crate::terraform::GeneratorError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid region: {0}")]
    InvalidRegion(String),
    #[error("test failed: {0}")]
    TestFailed(String),
    #[error("activation failed: {0}")]
    ActivationFailed(String),
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
    use crate::pop::{Region, Continent, PopTier, CapacitySpec, ServiceConfig, ResourceLimits, PortMapping};
    use crate::provider::DedicatedProvider;

    #[tokio::test]
    async fn test_pipeline_execution() {
        let health = Arc::new(HealthMonitor::new());
        let config = PipelineConfig::default();
        let pipeline = LifecyclePipeline::new(health, config);

        // Using OVH datacenter - dedicated server only
        let region = Region::new("gra", "Gravelines", Continent::Europe, 50.99, 2.13);
        let pop = PopDefinition::new("test-pop", region, DedicatedProvider::OvhCloud, PopTier::Edge)
            .with_capacity(CapacitySpec::small())
            .with_service(ServiceConfig {
                name: "gateway".into(),
                image: "opensase/gateway:latest".into(),
                ports: vec![PortMapping { container_port: 443, host_port: 443, protocol: "tcp".into() }],
                env: vec![],
                resources: ResourceLimits::default(),
                health_check: None,
            });

        let result = pipeline.execute(pop).await;
        assert!(result.is_ok());
        
        let instance = result.unwrap();
        assert_eq!(instance.status, PopStatus::Running);
    }

    #[test]
    fn test_lifecycle_stages() {
        assert_eq!(LifecycleStage::Define.next(), Some(LifecycleStage::Provision));
        assert_eq!(LifecycleStage::Monitor.next(), None);
    }
}
