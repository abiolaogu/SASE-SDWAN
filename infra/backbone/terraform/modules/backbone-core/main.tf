# OpenSASE Private Backbone - Core Module
# Unified backbone management

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    megaport = {
      source  = "megaport/megaport"
      version = "~> 0.4"
    }
    packetfabric = {
      source  = "PacketFabric/packetfabric"
      version = "~> 1.6"
    }
  }
}

# ===========================================
# Variables
# ===========================================

variable "backbone_config" {
  description = "Complete backbone configuration"
  type = object({
    name        = string
    environment = string
    topology    = string  # full_mesh, hub_spoke, regional_mesh
    
    providers = object({
      primary              = string  # megaport, packetfabric
      enable_redundancy    = bool
      megaport_api_key     = optional(string)
      packetfabric_api_key = optional(string)
      packetfabric_account = optional(string)
    })
    
    optimization = object({
      mode          = string  # performance, balanced, cost
      max_latency_ms = number
      burst_enabled = bool
    })
  })
}

variable "pops" {
  description = "PoP definitions"
  type = map(object({
    name           = string
    region         = string
    provider       = string  # equinix, ovh, hetzner, etc.
    tier           = string  # tier1, tier2, tier3
    bandwidth_mbps = number
    vlan_data      = number
    vlan_control   = number
  }))
}

# ===========================================
# Provider Configuration
# ===========================================

provider "megaport" {
  access_key           = var.backbone_config.providers.megaport_api_key
  environment          = var.backbone_config.environment == "production" ? "production" : "staging"
  accept_purchase_terms = true
}

provider "packetfabric" {
  host  = "https://api.packetfabric.com"
  token = var.backbone_config.providers.packetfabric_api_key
}

# ===========================================
# VXC Mesh Deployment
# ===========================================

module "vxc_mesh" {
  source = "../vxc-mesh"
  
  backbone_name = var.backbone_config.name
  
  pops = {
    for k, pop in var.pops : k => {
      name           = pop.name
      region         = pop.region
      tier           = pop.tier
      bandwidth_mbps = pop.bandwidth_mbps
      vlan_id        = pop.vlan_data
      latency_group  = pop.region == "us-east" || pop.region == "eu-west" ? "low" : "medium"
    }
  }
  
  provider_preference    = var.backbone_config.providers.primary
  enable_redundancy      = var.backbone_config.providers.enable_redundancy
  max_latency_ms         = var.backbone_config.optimization.max_latency_ms
  cost_optimization      = var.backbone_config.optimization.mode
  packetfabric_account_uuid = var.backbone_config.providers.packetfabric_account
}

# ===========================================
# Bandwidth Monitoring
# ===========================================

resource "local_file" "monitoring_config" {
  filename = "${path.module}/generated/monitoring.yaml"
  
  content = yamlencode({
    backbone = var.backbone_config.name
    
    prometheus_targets = [
      for k, pop in var.pops : {
        job_name = "ospb-${k}"
        targets  = ["${pop.name}:9100"]
        labels = {
          pop      = k
          region   = pop.region
          provider = pop.provider
        }
      }
    ]
    
    alerts = {
      bandwidth_threshold = 80
      latency_threshold   = var.backbone_config.optimization.max_latency_ms
      packet_loss_threshold = 0.1
    }
    
    grafana_dashboards = [
      "ospb-overview",
      "ospb-latency-matrix",
      "ospb-bandwidth-utilization",
      "ospb-cost-tracking"
    ]
  })
}

# ===========================================
# Cost Tracking
# ===========================================

resource "local_file" "cost_report" {
  filename = "${path.module}/generated/cost-estimate.json"
  
  content = jsonencode({
    backbone     = var.backbone_config.name
    environment  = var.backbone_config.environment
    generated_at = timestamp()
    
    pops = {
      for k, pop in var.pops : k => {
        bandwidth = pop.bandwidth_mbps
        tier      = pop.tier
        estimated_monthly = (
          pop.tier == "tier1" ? 2500 :
          pop.tier == "tier2" ? 1200 :
          600
        )
      }
    }
    
    summary = {
      total_pops            = length(var.pops)
      tier1_pops            = length([for p in var.pops : p if p.tier == "tier1"])
      tier2_pops            = length([for p in var.pops : p if p.tier == "tier2"])
      tier3_pops            = length([for p in var.pops : p if p.tier == "tier3"])
      redundancy_enabled    = var.backbone_config.providers.enable_redundancy
      estimated_total_monthly = sum([
        for p in var.pops : (
          p.tier == "tier1" ? 2500 :
          p.tier == "tier2" ? 1200 :
          600
        )
      ]) * (var.backbone_config.providers.enable_redundancy ? 1.5 : 1)
    }
  })
}

# ===========================================
# Ansible Inventory for Backbone
# ===========================================

resource "local_file" "backbone_inventory" {
  filename = "${path.module}/../../ansible/inventory/backbone.yml"
  
  content = yamlencode({
    all = {
      children = {
        backbone_nodes = {
          hosts = {
            for k, pop in var.pops : k => {
              pop_name   = pop.name
              region     = pop.region
              tier       = pop.tier
              vlan_data  = pop.vlan_data
              vlan_control = pop.vlan_control
            }
          }
          vars = {
            backbone_name = var.backbone_config.name
            optimization  = var.backbone_config.optimization.mode
          }
        }
      }
    }
  })
}

# ===========================================
# Outputs
# ===========================================

output "backbone_info" {
  value = {
    name             = var.backbone_config.name
    environment      = var.backbone_config.environment
    topology         = var.backbone_config.topology
    primary_provider = var.backbone_config.providers.primary
    redundancy       = var.backbone_config.providers.enable_redundancy
  }
}

output "mesh_info" {
  value = module.vxc_mesh.mesh_topology
}

output "estimated_costs" {
  value = module.vxc_mesh.estimated_monthly_cost
}

output "config_files" {
  value = {
    monitoring    = local_file.monitoring_config.filename
    cost_report   = local_file.cost_report.filename
    inventory     = local_file.backbone_inventory.filename
    routing       = module.vxc_mesh.routing_policy_path
    bgp           = module.vxc_mesh.bgp_config_path
  }
}
