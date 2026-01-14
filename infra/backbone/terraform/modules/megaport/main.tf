# OpenSASE Private Backbone - Megaport Module
# On-demand Virtual Cross-Connects for private middle-mile

terraform {
  required_providers {
    megaport = {
      source  = "megaport/megaport"
      version = "~> 0.4"
    }
  }
}

# ===========================================
# Variables
# ===========================================

variable "backbone_name" {
  description = "Backbone network identifier"
  type        = string
  default     = "ospb"
}

variable "pop_locations" {
  description = "PoP locations requiring Megaport connectivity"
  type = map(object({
    name              = string
    megaport_location = string  # Megaport location ID
    port_speed_mbps   = number  # 1000, 10000, 100000
    vlan_id           = number
    bandwidth_mbps    = number  # VXC bandwidth
  }))
}

variable "topology" {
  description = "Backbone topology: full_mesh or hub_spoke"
  type        = string
  default     = "full_mesh"
  
  validation {
    condition     = contains(["full_mesh", "hub_spoke"], var.topology)
    error_message = "Topology must be full_mesh or hub_spoke"
  }
}

variable "hub_location" {
  description = "Hub location for hub_spoke topology"
  type        = string
  default     = ""
}

variable "environment" {
  type    = string
  default = "production"
}

# ===========================================
# Locals
# ===========================================

locals {
  # Megaport location mappings
  location_ids = {
    # North America
    "nyc"     = "Equinix NY5"
    "lax"     = "Equinix LA1"
    "chi"     = "Equinix CH1"
    "dal"     = "Equinix DA1"
    "ash"     = "Equinix DC2"
    "sea"     = "Equinix SE2"
    "sfo"     = "Equinix SV1"
    "mia"     = "Equinix MI1"
    
    # Europe
    "ams"     = "Equinix AM5"
    "lon"     = "Equinix LD5"
    "fra"     = "Equinix FR5"
    "par"     = "Equinix PA3"
    
    # Asia Pacific
    "sin"     = "Equinix SG3"
    "tok"     = "Equinix TY2"
    "syd"     = "Equinix SY3"
    "hkg"     = "Equinix HK2"
  }
  
  # Generate VXC pairs for full mesh
  pop_list = keys(var.pop_locations)
  
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
  
  # Hub-spoke pairs
  hub_spoke_pairs = var.topology == "hub_spoke" ? [
    for pop in local.pop_list : {
      a     = var.hub_location
      b     = pop
      key   = "${var.hub_location}-${pop}"
      speed = var.pop_locations[pop].bandwidth_mbps
    } if pop != var.hub_location
  ] : []
  
  vxc_pairs = var.topology == "full_mesh" ? local.full_mesh_pairs : local.hub_spoke_pairs
}

# ===========================================
# Megaport Ports at Each PoP
# ===========================================

resource "megaport_port" "pop" {
  for_each = var.pop_locations
  
  port_name   = "OSPB-${each.key}-${var.environment}"
  port_speed  = each.value.port_speed_mbps
  location_id = lookup(local.location_ids, each.value.megaport_location, each.value.megaport_location)
  term        = 12  # 12-month term for better pricing
  
  # Cost allocation tag
  cost_centre = "ospb-${each.key}"
}

# ===========================================
# Virtual Cross-Connects (VXCs)
# ===========================================

resource "megaport_vxc" "backbone" {
  for_each = { for pair in local.vxc_pairs : pair.key => pair }
  
  vxc_name   = "OSPB-${each.value.a}-${each.value.b}"
  rate_limit = each.value.speed
  
  a_end {
    port_id  = megaport_port.pop[each.value.a].id
    vlan     = var.pop_locations[each.value.a].vlan_id
  }
  
  b_end {
    port_id  = megaport_port.pop[each.value.b].id
    vlan     = var.pop_locations[each.value.b].vlan_id
  }
  
  # Prefer low-latency routing
  service_level = "private"
}

# ===========================================
# Megaport Cloud Router (MCR) - Optional
# ===========================================

resource "megaport_mcr" "hub" {
  count = var.topology == "hub_spoke" ? 1 : 0
  
  mcr_name    = "OSPB-MCR-${var.hub_location}"
  location_id = lookup(local.location_ids, var.hub_location, var.hub_location)
  router_asn  = 65100
  rate_limit  = 10000
  
  prefix_filter_lists = [
    {
      description     = "Allow RFC1918"
      address_family  = "IPv4"
      entries = [
        { action = "permit", prefix = "10.0.0.0/8", ge = 8, le = 32 },
        { action = "permit", prefix = "172.16.0.0/12", ge = 12, le = 32 },
        { action = "permit", prefix = "192.168.0.0/16", ge = 16, le = 32 }
      ]
    }
  ]
}

# ===========================================
# Outputs
# ===========================================

output "ports" {
  description = "Megaport ports at each PoP"
  value = {
    for k, port in megaport_port.pop : k => {
      id        = port.id
      name      = port.port_name
      speed     = port.port_speed
      location  = port.location_id
      status    = port.provisioning_status
    }
  }
}

output "vxcs" {
  description = "Virtual Cross-Connects"
  value = {
    for k, vxc in megaport_vxc.backbone : k => {
      id         = vxc.id
      name       = vxc.vxc_name
      bandwidth  = vxc.rate_limit
      a_end_port = vxc.a_end[0].port_id
      b_end_port = vxc.b_end[0].port_id
      status     = vxc.provisioning_status
    }
  }
}

output "topology_info" {
  value = {
    type            = var.topology
    total_ports     = length(megaport_port.pop)
    total_vxcs      = length(megaport_vxc.backbone)
    hub_location    = var.topology == "hub_spoke" ? var.hub_location : null
  }
}

output "monthly_cost_estimate" {
  description = "Estimated monthly cost"
  value = {
    port_costs = sum([for port in megaport_port.pop : 
      port.port_speed == 1000 ? 500 :
      port.port_speed == 10000 ? 1500 :
      port.port_speed == 100000 ? 5000 : 0
    ])
    vxc_costs = sum([for vxc in megaport_vxc.backbone :
      vxc.rate_limit <= 1000 ? 100 :
      vxc.rate_limit <= 10000 ? 500 :
      vxc.rate_limit <= 50000 ? 2000 : 5000
    ])
  }
}
