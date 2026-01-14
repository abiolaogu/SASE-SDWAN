# OBMO Equinix Metal Module (TIER 1 - GLOBAL COVERAGE)
# 100 Gbps capable with BGP Anycast

terraform {
  required_providers {
    equinix = {
      source  = "equinix/equinix"
      version = "~> 1.14"
    }
  }
}

# ===========================================
# Variables
# ===========================================

variable "pop_config" {
  description = "PoP configuration object"
  type = object({
    name           = string
    metro          = string  # ny, ld, am, sg, ty, etc.
    environment    = string
    controller_url = string
    activation_key = string
  })
}

variable "project_id" {
  description = "Equinix Metal project ID"
  type        = string
}

variable "high_performance" {
  description = "Use 100G capable servers"
  type        = bool
  default     = true
}

variable "enable_ha" {
  description = "Enable HA with secondary server"
  type        = bool
  default     = true
}

variable "reservation_id" {
  description = "Hardware reservation ID for consistent performance"
  type        = string
  default     = ""
}

variable "ssh_public_keys" {
  description = "SSH public keys for access"
  type        = list(string)
  default     = []
}

# ===========================================
# Locals
# ===========================================

locals {
  # Server plans optimized for 100 Gbps networking
  # m3.large.x86: 32 cores, 256GB RAM, 2x25GbE (Intel XXV710)
  # n3.xlarge.x86: 32 cores, 512GB RAM, 2x100GbE (Mellanox ConnectX-6)
  server_plan = var.high_performance ? "n3.xlarge.x86" : "m3.large.x86"
  
  nic_info = {
    "n3.xlarge.x86" = { type = "mellanox_cx6", speed = 200 }
    "m3.large.x86"  = { type = "intel_xxv710", speed = 50 }
  }
  
  tags = [
    "opensase",
    "obmo",
    "pop:${var.pop_config.name}",
    "env:${var.pop_config.environment}",
    "100gbps"
  ]
}

# ===========================================
# SSH Keys
# ===========================================

resource "equinix_metal_project_ssh_key" "obmo" {
  count = length(var.ssh_public_keys) > 0 ? length(var.ssh_public_keys) : 0
  
  name       = "obmo-${var.pop_config.name}-${count.index}"
  public_key = var.ssh_public_keys[count.index]
  project_id = var.project_id
}

# ===========================================
# Primary PoP Server
# ===========================================

resource "equinix_metal_device" "pop_primary" {
  hostname         = "opensase-${var.pop_config.name}-01"
  plan             = local.server_plan
  metro            = var.pop_config.metro
  operating_system = "ubuntu_22_04"
  billing_cycle    = "hourly"
  project_id       = var.project_id
  
  # Cloud-init for automated setup
  user_data = templatefile("${path.module}/templates/cloud-init.yaml.tpl", {
    pop_name       = var.pop_config.name
    controller_url = var.pop_config.controller_url
    activation_key = var.pop_config.activation_key
    role           = "primary"
    nic_type       = local.nic_info[local.server_plan].type
    nic_speed      = local.nic_info[local.server_plan].speed
  })
  
  # Hardware reservation for consistent performance
  hardware_reservation_id = var.reservation_id != "" ? var.reservation_id : null
  
  project_ssh_key_ids = length(var.ssh_public_keys) > 0 ? [
    for key in equinix_metal_project_ssh_key.obmo : key.id
  ] : null
  
  tags = concat(local.tags, ["role:primary"])
  
  lifecycle {
    ignore_changes = [user_data]
  }
}

# ===========================================
# Secondary Server for HA
# ===========================================

resource "equinix_metal_device" "pop_secondary" {
  count = var.enable_ha ? 1 : 0
  
  hostname         = "opensase-${var.pop_config.name}-02"
  plan             = local.server_plan
  metro            = var.pop_config.metro
  operating_system = "ubuntu_22_04"
  billing_cycle    = "hourly"
  project_id       = var.project_id
  
  user_data = templatefile("${path.module}/templates/cloud-init.yaml.tpl", {
    pop_name       = var.pop_config.name
    controller_url = var.pop_config.controller_url
    activation_key = var.pop_config.activation_key
    role           = "secondary"
    nic_type       = local.nic_info[local.server_plan].type
    nic_speed      = local.nic_info[local.server_plan].speed
  })
  
  project_ssh_key_ids = length(var.ssh_public_keys) > 0 ? [
    for key in equinix_metal_project_ssh_key.obmo : key.id
  ] : null
  
  tags = concat(local.tags, ["role:secondary"])
  
  lifecycle {
    ignore_changes = [user_data]
  }
}

# ===========================================
# Reserved IPs for Anycast
# ===========================================

resource "equinix_metal_reserved_ip_block" "anycast_v4" {
  project_id  = var.project_id
  metro       = var.pop_config.metro
  type        = "public_ipv4"
  quantity    = 8
  description = "OpenSASE Anycast IPs - ${var.pop_config.name}"
  tags        = local.tags
}

resource "equinix_metal_reserved_ip_block" "anycast_v6" {
  project_id  = var.project_id
  metro       = var.pop_config.metro
  type        = "public_ipv6"
  quantity    = 1  # /56 block
  description = "OpenSASE Anycast IPv6 - ${var.pop_config.name}"
  tags        = local.tags
}

# ===========================================
# Attach IPs to Primary Server
# ===========================================

resource "equinix_metal_ip_attachment" "primary_anycast" {
  device_id     = equinix_metal_device.pop_primary.id
  cidr_notation = "${equinix_metal_reserved_ip_block.anycast_v4.address}/${equinix_metal_reserved_ip_block.anycast_v4.cidr}"
}

# ===========================================
# BGP Sessions for Anycast
# ===========================================

resource "equinix_metal_bgp_session" "primary_bgp_v4" {
  device_id      = equinix_metal_device.pop_primary.id
  address_family = "ipv4"
}

resource "equinix_metal_bgp_session" "primary_bgp_v6" {
  device_id      = equinix_metal_device.pop_primary.id
  address_family = "ipv6"
}

resource "equinix_metal_bgp_session" "secondary_bgp_v4" {
  count = var.enable_ha ? 1 : 0
  
  device_id      = equinix_metal_device.pop_secondary[0].id
  address_family = "ipv4"
}

# ===========================================
# Private VLAN for Inter-Server Communication
# ===========================================

resource "equinix_metal_vlan" "pop_private" {
  metro       = var.pop_config.metro
  project_id  = var.project_id
  description = "OpenSASE Private VLAN - ${var.pop_config.name}"
}

resource "equinix_metal_vlan" "pop_management" {
  metro       = var.pop_config.metro
  project_id  = var.project_id
  description = "OpenSASE Management VLAN - ${var.pop_config.name}"
}

# ===========================================
# VLAN Attachments
# ===========================================

resource "equinix_metal_port_vlan_attachment" "primary_private" {
  device_id = equinix_metal_device.pop_primary.id
  port_name = "bond0"
  vlan_vnid = equinix_metal_vlan.pop_private.vxlan
}

resource "equinix_metal_port_vlan_attachment" "secondary_private" {
  count = var.enable_ha ? 1 : 0
  
  device_id = equinix_metal_device.pop_secondary[0].id
  port_name = "bond0"
  vlan_vnid = equinix_metal_vlan.pop_private.vxlan
}

# ===========================================
# Metal Gateway for Hybrid Connectivity
# ===========================================

resource "equinix_metal_gateway" "pop_gateway" {
  project_id        = var.project_id
  vlan_id           = equinix_metal_vlan.pop_private.id
  ip_reservation_id = equinix_metal_reserved_ip_block.anycast_v4.id
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  description = "PoP deployment information"
  value = {
    pop_name     = var.pop_config.name
    metro        = var.pop_config.metro
    server_plan  = local.server_plan
    nic_type     = local.nic_info[local.server_plan].type
    nic_speed    = local.nic_info[local.server_plan].speed
    primary_ip   = equinix_metal_device.pop_primary.access_public_ipv4
    secondary_ip = var.enable_ha ? equinix_metal_device.pop_secondary[0].access_public_ipv4 : null
    anycast_ips  = equinix_metal_reserved_ip_block.anycast_v4.address
    anycast_cidr = equinix_metal_reserved_ip_block.anycast_v4.cidr
    vlan_id      = equinix_metal_vlan.pop_private.vxlan
  }
}

output "public_ips" {
  value = concat(
    [equinix_metal_device.pop_primary.access_public_ipv4],
    var.enable_ha ? [equinix_metal_device.pop_secondary[0].access_public_ipv4] : []
  )
}

output "private_ips" {
  value = concat(
    [equinix_metal_device.pop_primary.access_private_ipv4],
    var.enable_ha ? [equinix_metal_device.pop_secondary[0].access_private_ipv4] : []
  )
}

output "anycast_block" {
  value = {
    ipv4_address = equinix_metal_reserved_ip_block.anycast_v4.address
    ipv4_cidr    = equinix_metal_reserved_ip_block.anycast_v4.cidr
    ipv4_gateway = equinix_metal_reserved_ip_block.anycast_v4.gateway
    ipv6_address = equinix_metal_reserved_ip_block.anycast_v6.address
  }
}

output "bgp_info" {
  value = {
    primary_session   = equinix_metal_bgp_session.primary_bgp_v4.id
    secondary_session = var.enable_ha ? equinix_metal_bgp_session.secondary_bgp_v4[0].id : null
  }
}

output "vlans" {
  value = {
    private    = equinix_metal_vlan.pop_private.vxlan
    management = equinix_metal_vlan.pop_management.vxlan
  }
}

output "ssh_commands" {
  value = concat(
    ["ssh root@${equinix_metal_device.pop_primary.access_public_ipv4}"],
    var.enable_ha ? ["ssh root@${equinix_metal_device.pop_secondary[0].access_public_ipv4}"] : []
  )
}
