# OpenSASE Bare Metal Orchestrator - Equinix Metal Module
# 100+ Gbps Dedicated Servers with BGP Anycast

terraform {
  required_providers {
    equinix = {
      source  = "equinix/equinix"
      version = "~> 1.20"
    }
  }
}

# ===========================================
# Variables
# ===========================================

variable "project_id" {
  description = "Equinix Metal project ID"
  type        = string
}

variable "pop_name" {
  description = "PoP identifier (e.g., nyc1, ams1)"
  type        = string
}

variable "metro" {
  description = "Equinix metro code"
  type        = string
}

variable "plan" {
  description = "Server plan - n3.xlarge.x86 for 100G"
  type        = string
  default     = "n3.xlarge.x86"
}

variable "instance_count" {
  description = "Number of bare metal servers"
  type        = number
  default     = 2
}

variable "operating_system" {
  type    = string
  default = "ubuntu_22_04"
}

variable "ssh_keys" {
  type    = list(string)
  default = []
}

variable "enable_bgp" {
  type    = bool
  default = true
}

variable "bgp_asn" {
  type    = number
  default = 65100
}

variable "anycast_ips" {
  description = "Number of anycast IPs"
  type        = number
  default     = 4
}

variable "controller_url" {
  type    = string
  default = "https://manage.opensase.io"
}

variable "activation_key" {
  type      = string
  sensitive = true
}

variable "environment" {
  type    = string
  default = "production"
}

# ===========================================
# Locals
# ===========================================

locals {
  tags = [
    "opensase",
    "obmo",
    "pop-${var.pop_name}",
    "env-${var.environment}",
    "100gbps"
  ]
  
  # 100G capable plans
  high_perf_plans = {
    "n3.xlarge.x86" = { cores = 32, ram = 512, nic = "mellanox_cx6", speed = 200 }
    "m3.large.x86"  = { cores = 32, ram = 256, nic = "intel_xxv710", speed = 50 }
    "s3.xlarge.x86" = { cores = 24, ram = 192, nic = "intel_xxv710", speed = 50 }
  }
  
  server_spec = local.high_perf_plans[var.plan]
}

# ===========================================
# SSH Keys
# ===========================================

resource "equinix_metal_project_ssh_key" "obmo" {
  count = length(var.ssh_keys) == 0 ? 1 : 0
  
  name       = "obmo-${var.pop_name}"
  public_key = file("~/.ssh/opensase.pub")
  project_id = var.project_id
}

# ===========================================
# VLANs for Network Segmentation
# ===========================================

resource "equinix_metal_vlan" "data_plane" {
  metro       = var.metro
  project_id  = var.project_id
  description = "OBMO ${var.pop_name} data plane (100G traffic)"
}

resource "equinix_metal_vlan" "control_plane" {
  metro       = var.metro
  project_id  = var.project_id
  description = "OBMO ${var.pop_name} control plane"
}

resource "equinix_metal_vlan" "management" {
  metro       = var.metro
  project_id  = var.project_id
  description = "OBMO ${var.pop_name} management"
}

# ===========================================
# Reserved IP Blocks for Anycast
# ===========================================

resource "equinix_metal_reserved_ip_block" "anycast_v4" {
  count = var.enable_bgp ? 1 : 0
  
  project_id  = var.project_id
  metro       = var.metro
  quantity    = var.anycast_ips
  type        = "public_ipv4"
  description = "OBMO ${var.pop_name} anycast IPv4"
  tags        = local.tags
}

resource "equinix_metal_reserved_ip_block" "anycast_v6" {
  count = var.enable_bgp ? 1 : 0
  
  project_id  = var.project_id
  metro       = var.metro
  quantity    = 8
  type        = "public_ipv6"
  description = "OBMO ${var.pop_name} anycast IPv6"
  tags        = local.tags
}

# ===========================================
# Bare Metal Servers (100 Gbps)
# ===========================================

resource "equinix_metal_device" "server" {
  count = var.instance_count
  
  hostname         = "obmo-${var.pop_name}-${format("%02d", count.index + 1)}"
  plan             = var.plan
  metro            = var.metro
  operating_system = var.operating_system
  billing_cycle    = "hourly"
  project_id       = var.project_id
  
  project_ssh_key_ids = length(var.ssh_keys) > 0 ? var.ssh_keys : [
    equinix_metal_project_ssh_key.obmo[0].id
  ]
  
  # Network configuration for 100G
  ip_address {
    type = "public_ipv4"
  }
  ip_address {
    type = "private_ipv4"
  }
  ip_address {
    type = "public_ipv6"
  }
  
  # User data for 100G bootstrap
  user_data = templatefile("${path.module}/templates/100g-bootstrap.sh.tpl", {
    pop_name       = var.pop_name
    server_index   = count.index + 1
    server_count   = var.instance_count
    controller_url = var.controller_url
    activation_key = var.activation_key
    enable_bgp     = var.enable_bgp
    bgp_asn        = var.bgp_asn
    is_primary     = count.index == 0
    nic_type       = local.server_spec.nic
    nic_speed      = local.server_spec.speed
    worker_cores   = min(16, local.server_spec.cores - 2)
  })
  
  custom_data = jsonencode({
    obmo_version = "1.0.0"
    nic_config = {
      type  = local.server_spec.nic
      speed = local.server_spec.speed
    }
    anycast_ips = var.enable_bgp ? equinix_metal_reserved_ip_block.anycast_v4[0].address : null
  })
  
  tags = local.tags
  
  lifecycle {
    ignore_changes = [user_data]
  }
}

# ===========================================
# VLAN Attachments to Servers
# ===========================================

resource "equinix_metal_port_vlan_attachment" "data_plane" {
  count = var.instance_count
  
  device_id = equinix_metal_device.server[count.index].id
  port_name = "bond0"
  vlan_vnid = equinix_metal_vlan.data_plane.vxlan
}

resource "equinix_metal_port_vlan_attachment" "control_plane" {
  count = var.instance_count
  
  device_id = equinix_metal_device.server[count.index].id
  port_name = "bond0"
  vlan_vnid = equinix_metal_vlan.control_plane.vxlan
}

# ===========================================
# BGP Sessions for Anycast
# ===========================================

resource "equinix_metal_bgp_session" "ipv4" {
  count = var.enable_bgp ? var.instance_count : 0
  
  device_id      = equinix_metal_device.server[count.index].id
  address_family = "ipv4"
}

resource "equinix_metal_bgp_session" "ipv6" {
  count = var.enable_bgp ? var.instance_count : 0
  
  device_id      = equinix_metal_device.server[count.index].id
  address_family = "ipv6"
}

# ===========================================
# Anycast IP Assignment
# ===========================================

resource "equinix_metal_ip_attachment" "anycast" {
  count = var.enable_bgp ? 1 : 0
  
  device_id     = equinix_metal_device.server[0].id
  cidr_notation = "${equinix_metal_reserved_ip_block.anycast_v4[0].address}/${equinix_metal_reserved_ip_block.anycast_v4[0].cidr}"
}

# ===========================================
# Metal Gateway
# ===========================================

resource "equinix_metal_gateway" "pop" {
  count = var.enable_bgp ? 1 : 0
  
  project_id        = var.project_id
  vlan_id           = equinix_metal_vlan.data_plane.id
  ip_reservation_id = equinix_metal_reserved_ip_block.anycast_v4[0].id
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  value = {
    name       = var.pop_name
    metro      = var.metro
    plan       = var.plan
    nic_type   = local.server_spec.nic
    speed_gbps = local.server_spec.speed
    instances  = var.instance_count
  }
}

output "server_ids" {
  value = [for s in equinix_metal_device.server : s.id]
}

output "public_ips" {
  value = [for s in equinix_metal_device.server : s.access_public_ipv4]
}

output "private_ips" {
  value = [for s in equinix_metal_device.server : s.access_private_ipv4]
}

output "anycast_block" {
  value = var.enable_bgp ? {
    ipv4_address = equinix_metal_reserved_ip_block.anycast_v4[0].address
    ipv4_cidr    = equinix_metal_reserved_ip_block.anycast_v4[0].cidr
    ipv4_gateway = equinix_metal_reserved_ip_block.anycast_v4[0].gateway
    ipv6_address = equinix_metal_reserved_ip_block.anycast_v6[0].address
  } : null
}

output "bgp_info" {
  value = var.enable_bgp ? {
    asn      = var.bgp_asn
    sessions = [for s in equinix_metal_bgp_session.ipv4 : s.id]
  } : null
}

output "vlans" {
  value = {
    data_plane    = equinix_metal_vlan.data_plane.vxlan
    control_plane = equinix_metal_vlan.control_plane.vxlan
    management    = equinix_metal_vlan.management.vxlan
  }
}

output "ssh_commands" {
  value = [for s in equinix_metal_device.server : "ssh root@${s.access_public_ipv4}"]
}
