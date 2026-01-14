# OpenSASE Private Backbone - Enhanced Megaport Module
# Point-to-point VXC with dynamic port creation

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

variable "port_speed_mbps" {
  description = "Port speed for new ports"
  type        = number
  default     = 10000
}

variable "contract_term_months" {
  description = "Contract term (1, 12, 24, 36)"
  type        = number
  default     = 1
}

variable "enable_cost_optimization" {
  description = "Enable cost optimization features"
  type        = bool
  default     = false
}

# ===========================================
# Data Sources - Megaport Locations
# ===========================================

data "megaport_location" "pop_a" {
  name = var.backbone_config.pop_a.location
}

data "megaport_location" "pop_b" {
  name = var.backbone_config.pop_b.location
}

# ===========================================
# Megaport at PoP A (create if not exists)
# ===========================================

resource "megaport_port" "pop_a" {
  count = var.backbone_config.pop_a.port_id == "" ? 1 : 0
  
  product_name           = "OpenSASE-${var.backbone_config.pop_a.location}"
  location_id            = data.megaport_location.pop_a.id
  port_speed             = var.port_speed_mbps
  term                   = var.contract_term_months
  marketplace_visibility = false
  
  lifecycle {
    prevent_destroy = true
  }
}

# ===========================================
# Megaport at PoP B (create if not exists)
# ===========================================

resource "megaport_port" "pop_b" {
  count = var.backbone_config.pop_b.port_id == "" ? 1 : 0
  
  product_name           = "OpenSASE-${var.backbone_config.pop_b.location}"
  location_id            = data.megaport_location.pop_b.id
  port_speed             = var.port_speed_mbps
  term                   = var.contract_term_months
  marketplace_visibility = false
  
  lifecycle {
    prevent_destroy = true
  }
}

# ===========================================
# Locals - Port ID Resolution
# ===========================================

locals {
  port_a_id = var.backbone_config.pop_a.port_id != "" ? var.backbone_config.pop_a.port_id : megaport_port.pop_a[0].id
  port_b_id = var.backbone_config.pop_b.port_id != "" ? var.backbone_config.pop_b.port_id : megaport_port.pop_b[0].id
  
  # Cost estimation per Mbps (approximate)
  cost_per_mbps = {
    "1"   = 0.10  # Month-to-month
    "12"  = 0.08  # 1-year
    "24"  = 0.06  # 2-year
    "36"  = 0.05  # 3-year
  }
  
  monthly_cost_estimate = var.backbone_config.bandwidth_mbps * lookup(local.cost_per_mbps, tostring(var.contract_term_months), 0.10)
}

# ===========================================
# Virtual Cross Connect (VXC)
# ===========================================

resource "megaport_vxc" "backbone_link" {
  product_name = "OpenSASE-Backbone-${var.backbone_config.name}"
  rate_limit   = var.backbone_config.bandwidth_mbps
  
  a_end {
    product_uid = local.port_a_id
    vlan        = var.backbone_config.vlan_a
  }
  
  b_end {
    product_uid = local.port_b_id
    vlan        = var.backbone_config.vlan_b
  }
  
  # Service level for prioritized traffic
  service_level = "private"
}

# ===========================================
# A-End Config Generation
# ===========================================

resource "local_file" "a_end_config" {
  filename = "${path.module}/generated/${var.backbone_config.name}-a-end.conf"
  
  content = <<-EOF
# OSPB Link Configuration - A-End
# ${var.backbone_config.pop_a.location} → ${var.backbone_config.pop_b.location}

interface TenGigabitEthernet0/0/0.${var.backbone_config.vlan_a}
  description "OSPB: ${var.backbone_config.name}"
  encapsulation dot1q ${var.backbone_config.vlan_a}
  ip address dhcp
  mtu 9000
!
ip route ${var.backbone_config.pop_b.location}-networks via vlan${var.backbone_config.vlan_a}
EOF
}

# ===========================================
# B-End Config Generation
# ===========================================

resource "local_file" "b_end_config" {
  filename = "${path.module}/generated/${var.backbone_config.name}-b-end.conf"
  
  content = <<-EOF
# OSPB Link Configuration - B-End
# ${var.backbone_config.pop_b.location} → ${var.backbone_config.pop_a.location}

interface TenGigabitEthernet0/0/0.${var.backbone_config.vlan_b}
  description "OSPB: ${var.backbone_config.name}"
  encapsulation dot1q ${var.backbone_config.vlan_b}
  ip address dhcp
  mtu 9000
!
ip route ${var.backbone_config.pop_a.location}-networks via vlan${var.backbone_config.vlan_b}
EOF
}

# ===========================================
# Outputs
# ===========================================

output "vxc_info" {
  description = "VXC connection details"
  value = {
    vxc_id             = megaport_vxc.backbone_link.id
    name               = megaport_vxc.backbone_link.product_name
    bandwidth_mbps     = megaport_vxc.backbone_link.rate_limit
    a_end_location     = var.backbone_config.pop_a.location
    b_end_location     = var.backbone_config.pop_b.location
    a_end_vlan         = var.backbone_config.vlan_a
    b_end_vlan         = var.backbone_config.vlan_b
    status             = megaport_vxc.backbone_link.provisioning_status
    monthly_cost_estimate = local.monthly_cost_estimate
  }
}

output "port_ids" {
  value = {
    a_end = local.port_a_id
    b_end = local.port_b_id
  }
}

output "config_files" {
  value = {
    a_end = local_file.a_end_config.filename
    b_end = local_file.b_end_config.filename
  }
}
