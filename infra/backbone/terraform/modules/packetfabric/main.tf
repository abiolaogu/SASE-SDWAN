# OpenSASE Private Backbone - PacketFabric Module
# Alternative/Redundant middle-mile using PacketFabric

terraform {
  required_providers {
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

variable "pop_locations" {
  description = "PoP locations requiring PacketFabric connectivity"
  type = map(object({
    name               = string
    packetfabric_pop   = string  # PacketFabric PoP ID
    port_speed_gbps    = string  # 1Gbps, 10Gbps, 100Gbps
    service_class      = string  # longhaul, metro
    vlan_id            = number
    bandwidth_mbps     = number
  }))
}

variable "topology" {
  type    = string
  default = "full_mesh"
}

variable "hub_location" {
  type    = string
  default = ""
}

variable "account_uuid" {
  description = "PacketFabric account UUID"
  type        = string
}

variable "environment" {
  type    = string
  default = "production"
}

# ===========================================
# Locals
# ===========================================

locals {
  # PacketFabric PoP mappings
  pf_pops = {
    # North America
    "nyc"  = "NYC1"
    "lax"  = "LAX1"
    "chi"  = "CHI1"
    "dal"  = "DAL1"
    "ash"  = "WDC1"
    "sea"  = "SEA1"
    "sfo"  = "SFO1"
    "atl"  = "ATL1"
    "den"  = "DEN1"
    
    # Europe
    "ams"  = "AMS1"
    "lon"  = "LON1"
    "fra"  = "FRA1"
    
    # Asia Pacific
    "sin"  = "SIN1"
    "tok"  = "TKY1"
    "syd"  = "SYD1"
  }
  
  pop_list = keys(var.pop_locations)
  
  # Generate connection pairs
  full_mesh_pairs = var.topology == "full_mesh" ? flatten([
    for i, pop_a in local.pop_list : [
      for pop_b in slice(local.pop_list, i + 1, length(local.pop_list)) : {
        a     = pop_a
        b     = pop_b
        key   = "${pop_a}-${pop_b}"
        speed = min(var.pop_locations[pop_a].bandwidth_mbps, var.pop_locations[pop_b].bandwidth_mbps)
      }
    ]
  ]) : []
  
  hub_spoke_pairs = var.topology == "hub_spoke" ? [
    for pop in local.pop_list : {
      a     = var.hub_location
      b     = pop
      key   = "${var.hub_location}-${pop}"
      speed = var.pop_locations[pop].bandwidth_mbps
    } if pop != var.hub_location
  ] : []
  
  connection_pairs = var.topology == "full_mesh" ? local.full_mesh_pairs : local.hub_spoke_pairs
}

# ===========================================
# PacketFabric Ports
# ===========================================

resource "packetfabric_port" "pop" {
  for_each = var.pop_locations
  
  account_uuid = var.account_uuid
  
  description  = "OSPB-${each.key}-${var.environment}"
  pop          = lookup(local.pf_pops, each.value.packetfabric_pop, each.value.packetfabric_pop)
  speed        = each.value.port_speed_gbps
  media        = "LX"  # Single-mode fiber
  
  subscription_term = 12
  autoneg           = true
}

# ===========================================
# Backbone Virtual Circuits
# ===========================================

resource "packetfabric_backbone_virtual_circuit" "backbone" {
  for_each = { for pair in local.connection_pairs : pair.key => pair }
  
  description = "OSPB-${each.value.a}-${each.value.b}"
  epl         = false
  
  interface_a {
    port_circuit_id = packetfabric_port.pop[each.value.a].id
    vlan            = var.pop_locations[each.value.a].vlan_id
  }
  
  interface_z {
    port_circuit_id = packetfabric_port.pop[each.value.b].id
    vlan            = var.pop_locations[each.value.b].vlan_id
  }
  
  bandwidth {
    longhaul_type     = var.pop_locations[each.value.a].service_class
    speed             = "${each.value.speed}Mbps"
    subscription_term = 12
  }
}

# ===========================================
# PacketFabric Cloud Router (Optional)
# ===========================================

resource "packetfabric_cloud_router" "hub" {
  count = var.topology == "hub_spoke" ? 1 : 0
  
  account_uuid = var.account_uuid
  name         = "OSPB-CR-${var.hub_location}"
  asn          = 65100
  capacity     = "10Gbps"
  
  regions = ["US", "UK", "NL", "DE", "SG", "JP", "AU"]
}

# ===========================================
# Flex Bandwidth (Dynamic Scaling)
# ===========================================

resource "packetfabric_flex_bandwidth" "burst" {
  for_each = { for pair in local.connection_pairs : pair.key => pair if each.value.speed < 10000 }
  
  description         = "OSPB-Burst-${each.value.a}-${each.value.b}"
  vc_circuit_id       = packetfabric_backbone_virtual_circuit.backbone[each.key].id
  speed               = "${each.value.speed * 2}Mbps"  # 2x burst capability
  subscription_term   = 1
  
  lifecycle {
    ignore_changes = [speed]
  }
}

# ===========================================
# Outputs
# ===========================================

output "ports" {
  value = {
    for k, port in packetfabric_port.pop : k => {
      id          = port.id
      description = port.description
      pop         = port.pop
      speed       = port.speed
      status      = port.state
    }
  }
}

output "virtual_circuits" {
  value = {
    for k, vc in packetfabric_backbone_virtual_circuit.backbone : k => {
      id          = vc.id
      description = vc.description
      bandwidth   = vc.bandwidth[0].speed
      status      = vc.state
    }
  }
}

output "topology_info" {
  value = {
    type        = var.topology
    total_ports = length(packetfabric_port.pop)
    total_vcs   = length(packetfabric_backbone_virtual_circuit.backbone)
  }
}

output "monthly_cost_estimate" {
  description = "Estimated monthly cost (USD)"
  value = {
    port_costs = sum([for port in packetfabric_port.pop :
      port.speed == "1Gbps" ? 400 :
      port.speed == "10Gbps" ? 1200 :
      port.speed == "100Gbps" ? 4000 : 0
    ])
    vc_costs = sum([for vc in packetfabric_backbone_virtual_circuit.backbone :
      tonumber(replace(vc.bandwidth[0].speed, "Mbps", "")) <= 1000 ? 80 :
      tonumber(replace(vc.bandwidth[0].speed, "Mbps", "")) <= 10000 ? 400 : 1500
    ])
  }
}
