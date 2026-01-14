//! Terraform Code Generator

use crate::pop::PopDefinition;
use crate::provider::CloudProvider;
use handlebars::Handlebars;
use serde_json::json;

/// Terraform generator
pub struct TerraformGenerator {
    handlebars: Handlebars<'static>,
}

impl TerraformGenerator {
    pub fn new() -> Self {
        let mut hb = Handlebars::new();
        
        // Register templates
        hb.register_template_string("aws_main", AWS_MAIN_TEMPLATE).unwrap();
        hb.register_template_string("aws_vpc", AWS_VPC_TEMPLATE).unwrap();
        hb.register_template_string("gcp_main", GCP_MAIN_TEMPLATE).unwrap();
        hb.register_template_string("vultr_main", VULTR_MAIN_TEMPLATE).unwrap();
        
        Self { handlebars: hb }
    }

    /// Generate Terraform for PoP
    pub fn generate(&self, pop: &PopDefinition) -> Result<TerraformOutput, GeneratorError> {
        let data = self.build_template_data(pop);
        
        let main_tf = match pop.provider {
            CloudProvider::Aws => self.handlebars.render("aws_main", &data)?,
            CloudProvider::Gcp => self.handlebars.render("gcp_main", &data)?,
            CloudProvider::Vultr => self.handlebars.render("vultr_main", &data)?,
            _ => self.generate_generic(pop, &data)?,
        };

        let variables_tf = self.generate_variables(pop);
        let outputs_tf = self.generate_outputs(pop);

        Ok(TerraformOutput {
            main_tf,
            variables_tf,
            outputs_tf,
            provider_tf: self.generate_provider(pop),
        })
    }

    fn build_template_data(&self, pop: &PopDefinition) -> serde_json::Value {
        json!({
            "pop_id": pop.pop_id,
            "region": pop.region.code,
            "region_name": pop.region.name,
            "instance_type": pop.provider.instance_type(pop.capacity.vcpus, pop.capacity.memory_gb),
            "instance_count": pop.capacity.instance_count,
            "vpc_cidr": pop.network.vpc_cidr,
            "subnets": pop.network.subnets,
            "services": pop.services,
            "anycast_enabled": pop.network.anycast_enabled,
            "anycast_ip": pop.network.anycast_ip,
            "tags": pop.tags,
        })
    }

    fn generate_generic(&self, pop: &PopDefinition, _data: &serde_json::Value) -> Result<String, GeneratorError> {
        Ok(format!(r#"
# Generic Terraform for {} on {}
# Provider: {}

resource "null_resource" "pop_{}" {{
  provisioner "local-exec" {{
    command = "echo 'Deploying {} PoP'"
  }}
}}
"#, pop.pop_id, pop.region.code, pop.provider.terraform_provider(), pop.pop_id, pop.pop_id))
    }

    fn generate_variables(&self, pop: &PopDefinition) -> String {
        format!(r#"
variable "pop_id" {{
  default = "{}"
}}

variable "region" {{
  default = "{}"
}}

variable "instance_type" {{
  default = "{}"
}}

variable "instance_count" {{
  default = {}
}}
"#, pop.pop_id, pop.region.code, 
    pop.provider.instance_type(pop.capacity.vcpus, pop.capacity.memory_gb),
    pop.capacity.instance_count)
    }

    fn generate_outputs(&self, pop: &PopDefinition) -> String {
        format!(r#"
output "pop_id" {{
  value = "{}"
}}

output "public_ips" {{
  value = []  # Populated after apply
}}

output "private_ips" {{
  value = []
}}

output "anycast_ip" {{
  value = "{}"
}}
"#, pop.pop_id, pop.network.anycast_ip.as_deref().unwrap_or(""))
    }

    fn generate_provider(&self, pop: &PopDefinition) -> String {
        match pop.provider {
            CloudProvider::Aws => format!(r#"
provider "aws" {{
  region = "{}"
}}
"#, pop.region.code),
            CloudProvider::Gcp => format!(r#"
provider "google" {{
  project = var.gcp_project
  region  = "{}"
}}
"#, pop.region.code),
            _ => format!(r#"
provider "{}" {{
  # Configure via environment variables
}}
"#, pop.provider.terraform_provider()),
        }
    }
}

impl Default for TerraformGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Generated Terraform files
#[derive(Debug)]
pub struct TerraformOutput {
    pub main_tf: String,
    pub variables_tf: String,
    pub outputs_tf: String,
    pub provider_tf: String,
}

impl TerraformOutput {
    pub fn write_to_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("main.tf"), &self.main_tf)?;
        std::fs::write(dir.join("variables.tf"), &self.variables_tf)?;
        std::fs::write(dir.join("outputs.tf"), &self.outputs_tf)?;
        std::fs::write(dir.join("provider.tf"), &self.provider_tf)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("template error: {0}")]
    Template(#[from] handlebars::RenderError),
    #[error("unsupported provider")]
    UnsupportedProvider,
}

// AWS Template
const AWS_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Region: {{region}} ({{region_name}})

module "vpc" {
  source = "./modules/vpc"
  
  vpc_cidr = "{{vpc_cidr}}"
  pop_id   = "{{pop_id}}"
}

module "security_groups" {
  source = "./modules/security"
  vpc_id = module.vpc.vpc_id
}

resource "aws_instance" "pop" {
  count         = {{instance_count}}
  ami           = data.aws_ami.ubuntu.id
  instance_type = "{{instance_type}}"
  
  subnet_id              = module.vpc.public_subnet_ids[count.index % length(module.vpc.public_subnet_ids)]
  vpc_security_group_ids = [module.security_groups.pop_sg_id]
  
  user_data = templatefile("${path.module}/userdata.sh", {
    pop_id = "{{pop_id}}"
  })
  
  tags = {
    Name    = "{{pop_id}}-${count.index}"
    Project = "opensase"
  }
}

{{#if anycast_enabled}}
resource "aws_eip" "anycast" {
  count = {{instance_count}}
  vpc   = true
  
  tags = {
    Name = "{{pop_id}}-anycast-${count.index}"
  }
}
{{/if}}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}
"#;

const AWS_VPC_TEMPLATE: &str = r#"
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "${var.pop_id}-vpc"
  }
}
"#;

const GCP_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Region: {{region}}

resource "google_compute_network" "vpc" {
  name                    = "{{pop_id}}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public" {
  name          = "{{pop_id}}-public"
  ip_cidr_range = "{{vpc_cidr}}"
  region        = "{{region}}"
  network       = google_compute_network.vpc.id
}

resource "google_compute_instance" "pop" {
  count        = {{instance_count}}
  name         = "{{pop_id}}-${count.index}"
  machine_type = "{{instance_type}}"
  zone         = "{{region}}-a"
  
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }
  
  network_interface {
    subnetwork = google_compute_subnetwork.public.id
    access_config {}
  }
}
"#;

const VULTR_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Region: {{region}}

resource "vultr_instance" "pop" {
  count       = {{instance_count}}
  plan        = "{{instance_type}}"
  region      = "{{region}}"
  os_id       = 387  # Ubuntu 22.04
  label       = "{{pop_id}}-${count.index}"
  hostname    = "{{pop_id}}-${count.index}"
  
  enable_ipv6 = true
  
  tags = ["opensase", "pop"]
}

{{#if anycast_enabled}}
resource "vultr_reserved_ip" "anycast" {
  region   = "{{region}}"
  ip_type  = "v4"
  label    = "{{pop_id}}-anycast"
}
{{/if}}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pop::{Region, Continent, PopTier, CapacitySpec};

    #[test]
    fn test_terraform_generation() {
        let gen = TerraformGenerator::new();
        let region = Region::new("us-east-1", "US East", Continent::NorthAmerica, 39.0, -77.0);
        let pop = PopDefinition::new("test-pop", region, CloudProvider::Aws, PopTier::Core)
            .with_capacity(CapacitySpec::medium());

        let output = gen.generate(&pop).unwrap();
        
        assert!(output.main_tf.contains("test-pop"));
        assert!(output.variables_tf.contains("pop_id"));
    }
}
