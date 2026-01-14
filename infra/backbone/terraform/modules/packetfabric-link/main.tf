# OpenSASE Private Backbone - Enhanced PacketFabric Module
# Point-to-point backbone virtual circuit with flex bandwidth

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

variable "backbone_config" {
  description = "Single backbone link configuration"
  type = object({
    name           = string
    pop_a          = object({ location = string, port_id = string })
    pop_b          = object({ location = string, port_id = string })
    bandwidth_mbps = number
    vlan_a         = number
    vlan_b         = number
  })
}

variable "port_speed" {
  description = "Port speed for new ports"
  type        = string
  default     = "10Gbps"
}

variable "subscription_term" {
  description = "Subscription term in months"
  type        = number
  default     = 1
}

variable "enable_burst" {
  description = "Enable burst capacity"
  type        = bool
  default     = false
}

variable "burst_capacity" {
  description = "Burst capacity limit"
  type        = string
  default     = "100Gbps"
}

variable "longhaul_type" {
  description = "Longhaul type: dedicated or usage"
  type        = string
  default     = "dedicated"
}

# ===========================================
# PacketFabric Port at PoP A
# ===========================================

resource "packetfabric_port" "pop_a" {
  count = var.backbone_config.pop_a.port_id == "" ? 1 : 0
  
  description       = "OpenSASE-${var.backbone_config.pop_a.location}"
  media             = "LX"
  pop               = var.backbone_config.pop_a.location
  speed             = var.port_speed
  subscription_term = var.subscription_term
  zone              = "A"
  autoneg           = true
}

# ===========================================
# PacketFabric Port at PoP B
# ===========================================

resource "packetfabric_port" "pop_b" {
  count = var.backbone_config.pop_b.port_id == "" ? 1 : 0
  
  description       = "OpenSASE-${var.backbone_config.pop_b.location}"
  media             = "LX"
  pop               = var.backbone_config.pop_b.location
  speed             = var.port_speed
  subscription_term = var.subscription_term
  zone              = "A"
  autoneg           = true
}

# ===========================================
# Locals
# ===========================================

locals {
  port_a_id = var.backbone_config.pop_a.port_id != "" ? var.backbone_config.pop_a.port_id : packetfabric_port.pop_a[0].id
  port_b_id = var.backbone_config.pop_b.port_id != "" ? var.backbone_config.pop_b.port_id : packetfabric_port.pop_b[0].id
  
  # Cost estimation
  cost_per_mbps_dedicated = 0.08
  cost_per_mbps_usage     = 0.12
  
  monthly_cost_estimate = var.longhaul_type == "dedicated" ? (
    var.backbone_config.bandwidth_mbps * local.cost_per_mbps_dedicated
  ) : (
    var.backbone_config.bandwidth_mbps * local.cost_per_mbps_usage * 0.5  # Assume 50% utilization
  )
}

# ===========================================
# Backbone Virtual Circuit
# ===========================================

resource "packetfabric_backbone_virtual_circuit" "backbone_link" {
  description = "OpenSASE-Backbone-${var.backbone_config.name}"
  epl         = false
  
  bandwidth {
    longhaul_type     = var.longhaul_type
    speed             = "${var.backbone_config.bandwidth_mbps}Mbps"
    subscription_term = var.subscription_term
  }
  
  interface_a {
    port_circuit_id = local.port_a_id
    vlan            = var.backbone_config.vlan_a
  }
  
  interface_z {
    port_circuit_id = local.port_b_id
    vlan            = var.backbone_config.vlan_b
  }
}

# ===========================================
# Flex Bandwidth for Burst Capacity
# ===========================================

resource "packetfabric_flex_bandwidth" "burst" {
  count = var.enable_burst ? 1 : 0
  
  description       = "OpenSASE Burst Capacity - ${var.backbone_config.name}"
  subscription_term = 1
  capacity          = var.burst_capacity
  
  lifecycle {
    ignore_changes = [capacity]
  }
}

# ===========================================
# A-End VPP Configuration
# ===========================================

resource "local_file" "a_end_vpp_config" {
  filename = "${path.module}/generated/${var.backbone_config.name}-a-end-vpp.conf"
  
  content = <<-EOF
# VPP Configuration for OSPB Link A-End
# ${var.backbone_config.pop_a.location} → ${var.backbone_config.pop_b.location}

create sub TenGigabitEthernet0/0/0 ${var.backbone_config.vlan_a}
set interface state TenGigabitEthernet0/0/0.${var.backbone_config.vlan_a} up
set interface mtu 9000 TenGigabitEthernet0/0/0.${var.backbone_config.vlan_a}

# IP will be configured by orchestrator
comment { OSPB link: ${var.backbone_config.name} }
EOF
}

# ===========================================
# B-End VPP Configuration
# ===========================================

resource "local_file" "b_end_vpp_config" {
  filename = "${path.module}/generated/${var.backbone_config.name}-b-end-vpp.conf"
  
  content = <<-EOF
# VPP Configuration for OSPB Link B-End
# ${var.backbone_config.pop_b.location} → ${var.backbone_config.pop_a.location}

create sub TenGigabitEthernet0/0/0 ${var.backbone_config.vlan_b}
set interface state TenGigabitEthernet0/0/0.${var.backbone_config.vlan_b} up
set interface mtu 9000 TenGigabitEthernet0/0/0.${var.backbone_config.vlan_b}

comment { OSPB link: ${var.backbone_config.name} }
EOF
}

# ===========================================
# Outputs
# ===========================================

output "vxc_info" {
  description = "Virtual circuit details"
  value = {
    vc_id              = packetfabric_backbone_virtual_circuit.backbone_link.id
    name               = packetfabric_backbone_virtual_circuit.backbone_link.description
    bandwidth_mbps     = var.backbone_config.bandwidth_mbps
    longhaul_type      = var.longhaul_type
    a_end_location     = var.backbone_config.pop_a.location
    b_end_location     = var.backbone_config.pop_b.location
    a_end_vlan         = var.backbone_config.vlan_a
    b_end_vlan         = var.backbone_config.vlan_b
    status             = packetfabric_backbone_virtual_circuit.backbone_link.state
    burst_enabled      = var.enable_burst
    monthly_cost_estimate = local.monthly_cost_estimate
  }
}

output "port_ids" {
  value = {
    a_end = local.port_a_id
    b_end = local.port_b_id
  }
}

output "flex_bandwidth_id" {
  value = var.enable_burst ? packetfabric_flex_bandwidth.burst[0].id : null
}

output "config_files" {
  value = {
    a_end_vpp = local_file.a_end_vpp_config.filename
    b_end_vpp = local_file.b_end_vpp_config.filename
  }
}
