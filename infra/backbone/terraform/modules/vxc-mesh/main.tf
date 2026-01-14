# OpenSASE Private Backbone - VXC Mesh Orchestration
# Intelligent routing and multi-provider mesh management

terraform {
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

variable "backbone_name" {
  type    = string
  default = "ospb"
}

variable "pops" {
  description = "All PoP locations with connectivity requirements"
  type = map(object({
    name          = string
    region        = string  # us-east, us-west, eu-west, ap-southeast
    tier          = string  # tier1 (Megaport+PF), tier2 (PF only), tier3 (single)
    bandwidth_mbps = number
    vlan_id       = number
    latency_group = string  # low, medium, high
  }))
}

variable "provider_preference" {
  description = "Primary provider: megaport or packetfabric"
  type        = string
  default     = "megaport"
}

variable "enable_redundancy" {
  description = "Enable dual-provider redundancy"
  type        = bool
  default     = true
}

variable "max_latency_ms" {
  description = "Maximum acceptable latency between PoPs"
  type        = number
  default     = 50
}

variable "cost_optimization" {
  description = "Optimization mode: performance, balanced, cost"
  type        = string
  default     = "balanced"
}

# ===========================================
# Locals - Intelligent Routing
# ===========================================

locals {
  # Group PoPs by region for optimal routing
  regional_groups = {
    "us-east"      = [for k, v in var.pops : k if v.region == "us-east"]
    "us-west"      = [for k, v in var.pops : k if v.region == "us-west"]
    "eu-west"      = [for k, v in var.pops : k if v.region == "eu-west"]
    "eu-central"   = [for k, v in var.pops : k if v.region == "eu-central"]
    "ap-southeast" = [for k, v in var.pops : k if v.region == "ap-southeast"]
    "ap-east"      = [for k, v in var.pops : k if v.region == "ap-east"]
  }
  
  # Regional hub selection (lowest latency)
  regional_hubs = {
    for region, pops in local.regional_groups :
    region => length(pops) > 0 ? pops[0] : null
    if length(pops) > 0
  }
  
  # Cross-region connections (hub-to-hub)
  cross_region_pairs = flatten([
    for i, region_a in keys(local.regional_hubs) : [
      for region_b in slice(keys(local.regional_hubs), i + 1, length(keys(local.regional_hubs))) : {
        a      = local.regional_hubs[region_a]
        b      = local.regional_hubs[region_b]
        key    = "${region_a}-${region_b}"
        type   = "cross-region"
        speed  = min(
          var.pops[local.regional_hubs[region_a]].bandwidth_mbps,
          var.pops[local.regional_hubs[region_b]].bandwidth_mbps
        )
      }
    ]
  ])
  
  # Intra-region connections (full mesh within region)
  intra_region_pairs = flatten([
    for region, pops in local.regional_groups : [
      for i, pop_a in pops : [
        for pop_b in slice(pops, i + 1, length(pops)) : {
          a     = pop_a
          b     = pop_b
          key   = "${pop_a}-${pop_b}"
          type  = "intra-region"
          speed = min(var.pops[pop_a].bandwidth_mbps, var.pops[pop_b].bandwidth_mbps)
        }
      ]
    ]
  ])
  
  # All connections
  all_connections = concat(local.cross_region_pairs, local.intra_region_pairs)
  
  # Provider selection per connection
  connection_providers = {
    for conn in local.all_connections : conn.key => {
      primary   = conn.type == "cross-region" && var.enable_redundancy ? "megaport" : var.provider_preference
      secondary = var.enable_redundancy && var.pops[conn.a].tier == "tier1" ? (
        var.provider_preference == "megaport" ? "packetfabric" : "megaport"
      ) : null
    }
  }
  
  # Cost-optimized bandwidth
  optimized_bandwidth = {
    for conn in local.all_connections : conn.key => (
      var.cost_optimization == "performance" ? conn.speed :
      var.cost_optimization == "cost" ? floor(conn.speed * 0.5) :
      floor(conn.speed * 0.75)  # balanced
    )
  }
}

# ===========================================
# Megaport Connections (Primary)
# ===========================================

module "megaport_primary" {
  source = "../megaport"
  count  = var.provider_preference == "megaport" ? 1 : 0
  
  backbone_name = var.backbone_name
  topology      = "full_mesh"
  
  pop_locations = {
    for k, pop in var.pops : k => {
      name              = pop.name
      megaport_location = k
      port_speed_mbps   = pop.bandwidth_mbps >= 10000 ? 10000 : 1000
      vlan_id           = pop.vlan_id
      bandwidth_mbps    = local.optimized_bandwidth["${k}-${keys(var.pops)[0]}"] 
    } if pop.tier != "tier3"
  }
}

# ===========================================
# PacketFabric Connections (Secondary/Primary)
# ===========================================

module "packetfabric_backbone" {
  source = "../packetfabric"
  count  = var.provider_preference == "packetfabric" || var.enable_redundancy ? 1 : 0
  
  backbone_name = var.backbone_name
  topology      = "full_mesh"
  account_uuid  = var.packetfabric_account_uuid
  
  pop_locations = {
    for k, pop in var.pops : k => {
      name               = pop.name
      packetfabric_pop   = k
      port_speed_gbps    = pop.bandwidth_mbps >= 10000 ? "10Gbps" : "1Gbps"
      service_class      = pop.latency_group == "low" ? "metro" : "longhaul"
      vlan_id            = pop.vlan_id + 100  # Offset for redundancy
      bandwidth_mbps     = local.optimized_bandwidth["${k}-${keys(var.pops)[0]}"]
    } if pop.tier != "tier3" && (var.enable_redundancy || var.provider_preference == "packetfabric")
  }
}

variable "packetfabric_account_uuid" {
  type    = string
  default = ""
}

# ===========================================
# Routing Policy
# ===========================================

resource "local_file" "routing_policy" {
  filename = "${path.module}/generated/routing-policy.json"
  
  content = jsonencode({
    backbone_name = var.backbone_name
    strategy      = var.cost_optimization
    max_latency   = var.max_latency_ms
    
    regional_hubs = local.regional_hubs
    
    routing_rules = [
      for conn in local.all_connections : {
        source      = conn.a
        destination = conn.b
        type        = conn.type
        primary     = local.connection_providers[conn.key].primary
        secondary   = local.connection_providers[conn.key].secondary
        bandwidth   = local.optimized_bandwidth[conn.key]
      }
    ]
    
    failover = {
      detection_time_ms  = 1000
      failover_time_ms   = 5000
      health_check_interval = 10
    }
  })
}

# ===========================================
# BGP Route Configuration
# ===========================================

resource "local_file" "bgp_config" {
  filename = "${path.module}/generated/bgp-routes.conf"
  
  content = <<-EOF
# OSPB BGP Routing Configuration
# Auto-generated by Terraform

router bgp 65100
  bgp router-id auto
  bgp log-neighbor-changes
  
  # Regional hub peers
%{ for region, hub in local.regional_hubs ~}
  neighbor ${hub}-peer peer-group
  neighbor ${hub}-peer remote-as 65100
  neighbor ${hub}-peer update-source lo
  neighbor ${hub}-peer next-hop-self
  
%{ endfor ~}

  # Route policy
  address-family ipv4 unicast
    redistribute connected route-map OSPB-CONNECTED
    redistribute static route-map OSPB-STATIC
    maximum-paths 8
    maximum-paths ibgp 8
  exit-address-family

# Route maps
route-map OSPB-CONNECTED permit 10
  match interface lo
  set community 65100:100

route-map OSPB-STATIC permit 10
  set community 65100:200
EOF
}

# ===========================================
# Outputs
# ===========================================

output "mesh_topology" {
  value = {
    total_pops         = length(var.pops)
    total_connections  = length(local.all_connections)
    cross_region       = length(local.cross_region_pairs)
    intra_region       = length(local.intra_region_pairs)
    regional_hubs      = local.regional_hubs
    primary_provider   = var.provider_preference
    redundancy_enabled = var.enable_redundancy
  }
}

output "estimated_monthly_cost" {
  value = {
    megaport     = var.provider_preference == "megaport" ? try(module.megaport_primary[0].monthly_cost_estimate, null) : null
    packetfabric = var.enable_redundancy || var.provider_preference == "packetfabric" ? try(module.packetfabric_backbone[0].monthly_cost_estimate, null) : null
  }
}

output "routing_policy_path" {
  value = local_file.routing_policy.filename
}

output "bgp_config_path" {
  value = local_file.bgp_config.filename
}
