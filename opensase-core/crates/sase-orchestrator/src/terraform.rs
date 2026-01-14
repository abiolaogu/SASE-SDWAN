//! Terraform/Provisioning Code Generator for Dedicated Servers
//!
//! Generates infrastructure-as-code for dedicated server providers.
//! Note: Many dedicated providers use API-based provisioning rather than Terraform.

use crate::pop::PopDefinition;
use crate::provider::{DedicatedProvider, CloudProvider};
use handlebars::Handlebars;
use serde_json::json;

/// Terraform/Provisioning generator for dedicated servers
pub struct TerraformGenerator {
    handlebars: Handlebars<'static>,
}

impl TerraformGenerator {
    pub fn new() -> Self {
        let mut hb = Handlebars::new();
        
        // Register templates for dedicated server providers
        hb.register_template_string("hetzner_main", HETZNER_MAIN_TEMPLATE).unwrap();
        hb.register_template_string("ovh_main", OVH_MAIN_TEMPLATE).unwrap();
        hb.register_template_string("scaleway_main", SCALEWAY_MAIN_TEMPLATE).unwrap();
        hb.register_template_string("equinix_main", EQUINIX_MAIN_TEMPLATE).unwrap();
        hb.register_template_string("generic_main", GENERIC_MAIN_TEMPLATE).unwrap();
        
        Self { handlebars: hb }
    }

    /// Generate Terraform/provisioning code for PoP
    pub fn generate(&self, pop: &PopDefinition) -> Result<TerraformOutput, GeneratorError> {
        let data = self.build_template_data(pop);
        
        let main_tf = match pop.provider {
            DedicatedProvider::Hetzner => self.handlebars.render("hetzner_main", &data)?,
            DedicatedProvider::OvhCloud => self.handlebars.render("ovh_main", &data)?,
            DedicatedProvider::Scaleway => self.handlebars.render("scaleway_main", &data)?,
            DedicatedProvider::EquinixMetal => self.handlebars.render("equinix_main", &data)?,
            _ => self.handlebars.render("generic_main", &data)?,
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
        let server_config = pop.provider.server_config(pop.capacity.vcpus, pop.capacity.memory_gb);
        json!({
            "pop_id": pop.pop_id,
            "region": pop.region.code,
            "region_name": pop.region.name,
            "server_type": server_config.model,
            "instance_count": pop.capacity.instance_count,
            "vpc_cidr": pop.network.vpc_cidr,
            "subnets": pop.network.subnets,
            "services": pop.services,
            "anycast_enabled": pop.network.anycast_enabled,
            "anycast_ip": pop.network.anycast_ip,
            "tags": pop.tags,
            "provider_name": format!("{:?}", pop.provider),
        })
    }

    fn generate_variables(&self, pop: &PopDefinition) -> String {
        let server_config = pop.provider.server_config(pop.capacity.vcpus, pop.capacity.memory_gb);
        format!(r#"
variable "pop_id" {{
  description = "PoP identifier"
  default     = "{}"
}}

variable "region" {{
  description = "Datacenter location"
  default     = "{}"
}}

variable "server_type" {{
  description = "Dedicated server model"
  default     = "{}"
}}

variable "instance_count" {{
  description = "Number of servers"
  default     = {}
}}

variable "ssh_keys" {{
  description = "SSH public keys for server access"
  type        = list(string)
  default     = []
}}
"#, pop.pop_id, pop.region.code, server_config.model, pop.capacity.instance_count)
    }

    fn generate_outputs(&self, pop: &PopDefinition) -> String {
        format!(r#"
output "pop_id" {{
  description = "PoP identifier"
  value       = "{}"
}}

output "public_ips" {{
  description = "Public IP addresses of dedicated servers"
  value       = []  # Populated after provisioning
}}

output "private_ips" {{
  description = "Private network IPs"
  value       = []
}}

output "anycast_ip" {{
  description = "Anycast IP (if BGP enabled)"
  value       = "{}"
}}

output "provider" {{
  description = "Dedicated server provider"
  value       = "{:?}"
}}
"#, pop.pop_id, pop.network.anycast_ip.as_deref().unwrap_or(""), pop.provider)
    }

    fn generate_provider(&self, pop: &PopDefinition) -> String {
        match pop.provider {
            DedicatedProvider::Hetzner => format!(r#"
# Hetzner Cloud Provider (for cloud instances)
# For dedicated servers, use Robot API
terraform {{
  required_providers {{
    hcloud = {{
      source  = "hetznercloud/hcloud"
      version = "~> 1.42"
    }}
  }}
}}

provider "hcloud" {{
  token = var.hetzner_token
}}
"#),
            DedicatedProvider::OvhCloud => format!(r#"
# OVH Cloud Provider
terraform {{
  required_providers {{
    ovh = {{
      source  = "ovh/ovh"
      version = "~> 0.34"
    }}
  }}
}}

provider "ovh" {{
  endpoint           = "ovh-eu"
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}}
"#),
            DedicatedProvider::Scaleway => format!(r#"
# Scaleway Provider
terraform {{
  required_providers {{
    scaleway = {{
      source  = "scaleway/scaleway"
      version = "~> 2.28"
    }}
  }}
}}

provider "scaleway" {{
  zone   = "{}"
  region = "{}"
}}
"#, pop.region.code, pop.region.code.split('-').take(2).collect::<Vec<_>>().join("-")),
            DedicatedProvider::EquinixMetal => format!(r#"
# Equinix Metal Provider (Bare Metal)
terraform {{
  required_providers {{
    equinix = {{
      source  = "equinix/equinix"
      version = "~> 1.14"
    }}
  }}
}}

provider "equinix" {{
  auth_token = var.equinix_auth_token
}}
"#),
            _ => format!(r#"
# {} - Manual provisioning required
# Use provider's API or web console for dedicated server ordering
# This generates a provisioning script instead

terraform {{
  required_providers {{
    null = {{
      source  = "hashicorp/null"
      version = "~> 3.2"
    }}
  }}
}}
"#, format!("{:?}", pop.provider)),
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

// Hetzner Dedicated Server Template
const HETZNER_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Provider: Hetzner Dedicated Servers
# Datacenter: {{region}} ({{region_name}})

# Note: Hetzner dedicated servers are ordered via Robot API
# This uses hcloud for initial setup, then Robot for dedicated

resource "hcloud_server" "pop" {
  count       = {{instance_count}}
  name        = "{{pop_id}}-${count.index}"
  server_type = "{{server_type}}"
  location    = "{{region}}"
  image       = "ubuntu-22.04"
  
  ssh_keys = var.ssh_keys
  
  labels = {
    project = "opensase"
    pop_id  = "{{pop_id}}"
  }
}

resource "hcloud_network" "pop_network" {
  name     = "{{pop_id}}-network"
  ip_range = "{{vpc_cidr}}"
}

resource "hcloud_network_subnet" "pop_subnet" {
  network_id   = hcloud_network.pop_network.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "{{vpc_cidr}}"
}

resource "hcloud_firewall" "pop_fw" {
  name = "{{pop_id}}-firewall"
  
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = ["0.0.0.0/0"]
  }
  
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "443"
    source_ips = ["0.0.0.0/0"]
  }
  
  rule {
    direction = "in"
    protocol  = "udp"
    port      = "51820"
    source_ips = ["0.0.0.0/0"]
  }
}
"#;

// OVH Dedicated Server Template
const OVH_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Provider: OVH Cloud Dedicated Servers
# Datacenter: {{region}}

# Note: OVH dedicated servers require order via API then installation
# This template manages the server once provisioned

data "ovh_dedicated_server" "pop" {
  count        = {{instance_count}}
  service_name = var.ovh_server_names[count.index]
}

resource "ovh_me_installation_template" "opensase" {
  base_template_name = "ubuntu2204-server_64"
  template_name      = "opensase-{{pop_id}}"
  
  customization {
    change_log               = "OpenSASE PoP deployment"
    custom_hostname          = "{{pop_id}}"
    post_installation_script = var.post_install_script
    ssh_key_name            = var.ssh_key_name
  }
}

# Private network (vRack)
resource "ovh_vrack_dedicated_server" "pop" {
  count        = {{instance_count}}
  service_name = var.vrack_service_name
  server_id    = data.ovh_dedicated_server.pop[count.index].service_name
}
"#;

// Scaleway Dedicated Server Template
const SCALEWAY_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Provider: Scaleway Elastic Metal (Dedicated)
# Zone: {{region}}

resource "scaleway_baremetal_server" "pop" {
  count = {{instance_count}}
  name  = "{{pop_id}}-${count.index}"
  zone  = "{{region}}"
  offer = "{{server_type}}"
  os    = "ubuntu_jammy"
  
  ssh_key_ids = var.ssh_key_ids
  
  tags = ["opensase", "pop", "{{pop_id}}"]
}

resource "scaleway_vpc_private_network" "pop_network" {
  name = "{{pop_id}}-network"
  
  tags = ["opensase", "{{pop_id}}"]
}

resource "scaleway_flexible_ip" "pop_ip" {
  count = {{instance_count}}
  
  tags = ["opensase", "{{pop_id}}"]
}
"#;

// Equinix Metal Template
const EQUINIX_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Provider: Equinix Metal (Bare Metal)
# Metro: {{region}}

resource "equinix_metal_device" "pop" {
  count            = {{instance_count}}
  hostname         = "{{pop_id}}-${count.index}"
  plan             = "{{server_type}}"
  metro            = "{{region}}"
  operating_system = "ubuntu_22_04"
  billing_cycle    = "hourly"
  project_id       = var.equinix_project_id
  
  {{#if anycast_enabled}}
  ip_address {
    type = "public_ipv4"
    cidr = 31
  }
  {{/if}}
}

resource "equinix_metal_vlan" "pop_vlan" {
  metro       = "{{region}}"
  project_id  = var.equinix_project_id
  description = "{{pop_id}} private VLAN"
}

{{#if anycast_enabled}}
resource "equinix_metal_bgp_session" "pop_bgp" {
  count          = {{instance_count}}
  device_id      = equinix_metal_device.pop[count.index].id
  address_family = "ipv4"
}
{{/if}}
"#;

// Generic Template for providers without Terraform support
const GENERIC_MAIN_TEMPLATE: &str = r#"
# OpenSASE PoP: {{pop_id}}
# Provider: {{provider_name}} (Manual Provisioning)
# Location: {{region}}

# This provider requires manual ordering or API-based provisioning
# The following is a placeholder that generates a provisioning script

resource "null_resource" "pop_provisioner" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== OpenSASE PoP Provisioning ==="
      echo "Pop ID: {{pop_id}}"
      echo "Provider: {{provider_name}}"
      echo "Location: {{region}}"
      echo "Server Type: {{server_type}}"
      echo "Instance Count: {{instance_count}}"
      echo ""
      echo "Please order the following from {{provider_name}}:"
      echo "- {{instance_count}}x {{server_type}} dedicated server(s)"
      echo "- Location: {{region}}"
      echo "- OS: Ubuntu 22.04 LTS"
      echo "- Private network enabled"
      {{#if anycast_enabled}}
      echo "- BGP session for anycast"
      {{/if}}
    EOT
  }
}

# Server inventory (populated after manual provisioning)
resource "local_file" "inventory" {
  filename = "${path.module}/inventory.json"
  content  = jsonencode({
    pop_id     = "{{pop_id}}"
    provider   = "{{provider_name}}"
    region     = "{{region}}"
    servers    = []  # Add server IPs after provisioning
  })
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pop::{Region, Continent, PopTier, CapacitySpec};

    #[test]
    fn test_hetzner_terraform_generation() {
        let gen = TerraformGenerator::new();
        let region = Region::new("fsn1", "Falkenstein", Continent::Europe, 50.47, 12.37);
        let pop = PopDefinition::new("test-pop", region, DedicatedProvider::Hetzner, PopTier::Core)
            .with_capacity(CapacitySpec::medium());

        let output = gen.generate(&pop).unwrap();
        
        assert!(output.main_tf.contains("test-pop"));
        assert!(output.main_tf.contains("hcloud_server"));
        assert!(output.provider_tf.contains("hetznercloud/hcloud"));
    }

    #[test]
    fn test_ovh_terraform_generation() {
        let gen = TerraformGenerator::new();
        let region = Region::new("gra", "Gravelines", Continent::Europe, 50.99, 2.13);
        let pop = PopDefinition::new("eu-pop", region, DedicatedProvider::OvhCloud, PopTier::Edge)
            .with_capacity(CapacitySpec::small());

        let output = gen.generate(&pop).unwrap();
        
        assert!(output.main_tf.contains("eu-pop"));
        assert!(output.main_tf.contains("ovh_dedicated_server"));
    }

    #[test]
    fn test_generic_provider() {
        let gen = TerraformGenerator::new();
        let region = Region::new("ams", "Amsterdam", Continent::Europe, 52.37, 4.9);
        let pop = PopDefinition::new("vox-pop", region, DedicatedProvider::Voxility, PopTier::Core)
            .with_capacity(CapacitySpec::large());

        let output = gen.generate(&pop).unwrap();
        
        // Generic template should include provisioning instructions
        assert!(output.main_tf.contains("null_resource"));
        assert!(output.main_tf.contains("Voxility"));
    }
}
