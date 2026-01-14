# Equinix Metal PoP Module - 100 Gbps Bare Metal
# High-performance dedicated servers with BGP and Anycast

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
  description = "Name of the PoP (e.g., nyc1, lon1)"
  type        = string
}

variable "metro" {
  description = "Equinix metro code (e.g., ny, ld, sg, am)"
  type        = string
}

variable "plan" {
  description = "Server plan - use n3.xlarge.x86 for 100Gbps"
  type        = string
  default     = "m3.large.x86"
}

variable "operating_system" {
  description = "OS for the server"
  type        = string
  default     = "ubuntu_22_04"
}

variable "ssh_keys" {
  description = "SSH key IDs for access"
  type        = list(string)
}

variable "instance_count" {
  description = "Number of servers for HA"
  type        = number
  default     = 2
}

variable "ip_addresses" {
  description = "Number of anycast IP addresses"
  type        = number
  default     = 4
}

variable "enable_bgp" {
  description = "Enable BGP for anycast"
  type        = bool
  default     = true
}

variable "bgp_asn" {
  description = "BGP ASN for the PoP"
  type        = number
  default     = 65100
}

variable "controller_url" {
  description = "FlexiWAN controller URL"
  type        = string
  default     = "https://manage.opensase.io"
}

variable "activation_key" {
  description = "FlexiWAN activation key"
  type        = string
  sensitive   = true
}

variable "environment" {
  description = "Environment (production, staging)"
  type        = string
  default     = "production"
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}

# ===========================================
# Locals
# ===========================================

locals {
  common_tags = [
    "opensase",
    "pop-${var.pop_name}",
    "env-${var.environment}",
    "managed-by-terraform"
  ]
  
  # 100Gbps capable plans
  high_perf_plans = ["n3.xlarge.x86", "m3.large.x86", "s3.xlarge.x86"]
}

# ===========================================
# SSH Keys
# ===========================================

resource "equinix_metal_project_ssh_key" "pop" {
  count = length(var.ssh_keys) > 0 ? 0 : 1
  
  name       = "opensase-${var.pop_name}"
  public_key = file("~/.ssh/opensase.pub")
  project_id = var.project_id
}

# ===========================================
# VLAN for Private Connectivity
# ===========================================

resource "equinix_metal_vlan" "private" {
  metro       = var.metro
  project_id  = var.project_id
  description = "OpenSASE ${var.pop_name} private VLAN"
}

resource "equinix_metal_vlan" "management" {
  metro       = var.metro
  project_id  = var.project_id
  description = "OpenSASE ${var.pop_name} management VLAN"
}

# ===========================================
# Reserved IP Block for Anycast
# ===========================================

resource "equinix_metal_reserved_ip_block" "anycast" {
  count = var.enable_bgp ? 1 : 0
  
  project_id  = var.project_id
  metro       = var.metro
  quantity    = var.ip_addresses
  type        = "public_ipv4"
  description = "OpenSASE ${var.pop_name} anycast IPs"
  
  tags = concat(local.common_tags, ["anycast"])
}

resource "equinix_metal_reserved_ip_block" "ipv6" {
  project_id  = var.project_id
  metro       = var.metro
  quantity    = 8
  type        = "public_ipv6"
  description = "OpenSASE ${var.pop_name} IPv6 block"
  
  tags = local.common_tags
}

# ===========================================
# Bare Metal Servers
# ===========================================

resource "equinix_metal_device" "pop_server" {
  count = var.instance_count
  
  hostname         = "opensase-${var.pop_name}-${format("%02d", count.index + 1)}"
  plan             = var.plan
  metro            = var.metro
  operating_system = var.operating_system
  billing_cycle    = "hourly"
  project_id       = var.project_id
  
  project_ssh_key_ids = length(var.ssh_keys) > 0 ? var.ssh_keys : [equinix_metal_project_ssh_key.pop[0].id]
  
  # Network configuration
  ip_address {
    type = "public_ipv4"
  }
  
  ip_address {
    type = "private_ipv4"
  }
  
  ip_address {
    type = "public_ipv6"
  }
  
  # Custom user data for initial setup
  user_data = templatefile("${path.module}/templates/userdata.sh.tpl", {
    pop_name       = var.pop_name
    controller_url = var.controller_url
    activation_key = var.activation_key
    server_index   = count.index + 1
    enable_bgp     = var.enable_bgp
    bgp_asn        = var.bgp_asn
    is_primary     = count.index == 0
  })
  
  # Tags
  tags = concat(local.common_tags, [
    "server-${count.index + 1}",
    count.index == 0 ? "primary" : "secondary"
  ])
  
  # Hardware reservation (optional, for guaranteed capacity)
  # hardware_reservation_id = var.hardware_reservation_id
  
  # Custom IPs from reserved block
  custom_data = jsonencode({
    anycast_ips = var.enable_bgp ? equinix_metal_reserved_ip_block.anycast[0].address : null
    server_role = count.index == 0 ? "primary" : "secondary"
  })
  
  lifecycle {
    ignore_changes = [user_data]
  }
}

# ===========================================
# VLAN Attachments
# ===========================================

resource "equinix_metal_port_vlan_attachment" "private" {
  count = var.instance_count
  
  device_id = equinix_metal_device.pop_server[count.index].id
  port_name = "bond0"
  vlan_vnid = equinix_metal_vlan.private.vxlan
}

resource "equinix_metal_port_vlan_attachment" "management" {
  count = var.instance_count
  
  device_id = equinix_metal_device.pop_server[count.index].id
  port_name = "bond0"
  vlan_vnid = equinix_metal_vlan.management.vxlan
}

# ===========================================
# BGP Sessions for Anycast
# ===========================================

resource "equinix_metal_bgp_session" "ipv4" {
  count = var.enable_bgp ? var.instance_count : 0
  
  device_id      = equinix_metal_device.pop_server[count.index].id
  address_family = "ipv4"
}

resource "equinix_metal_bgp_session" "ipv6" {
  count = var.enable_bgp ? var.instance_count : 0
  
  device_id      = equinix_metal_device.pop_server[count.index].id
  address_family = "ipv6"
}

# ===========================================
# IP Attachments for Anycast
# ===========================================

resource "equinix_metal_ip_attachment" "anycast_primary" {
  count = var.enable_bgp ? 1 : 0
  
  device_id     = equinix_metal_device.pop_server[0].id
  cidr_notation = "${equinix_metal_reserved_ip_block.anycast[0].address}/${equinix_metal_reserved_ip_block.anycast[0].cidr}"
}

# ===========================================
# Gateway for Inter-PoP Connectivity
# ===========================================

resource "equinix_metal_gateway" "pop" {
  project_id        = var.project_id
  vlan_id           = equinix_metal_vlan.private.id
  ip_reservation_id = equinix_metal_reserved_ip_block.anycast[0].id
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  value = {
    name  = var.pop_name
    metro = var.metro
    plan  = var.plan
  }
}

output "server_ids" {
  value = [for s in equinix_metal_device.pop_server : s.id]
}

output "public_ips" {
  value = [for s in equinix_metal_device.pop_server : s.access_public_ipv4]
}

output "private_ips" {
  value = [for s in equinix_metal_device.pop_server : s.access_private_ipv4]
}

output "ipv6_addresses" {
  value = [for s in equinix_metal_device.pop_server : s.access_public_ipv6]
}

output "anycast_block" {
  value = var.enable_bgp ? {
    address = equinix_metal_reserved_ip_block.anycast[0].address
    cidr    = equinix_metal_reserved_ip_block.anycast[0].cidr
    gateway = equinix_metal_reserved_ip_block.anycast[0].gateway
  } : null
}

output "bgp_sessions" {
  value = var.enable_bgp ? {
    ipv4 = [for s in equinix_metal_bgp_session.ipv4 : s.id]
    ipv6 = [for s in equinix_metal_bgp_session.ipv6 : s.id]
  } : null
}

output "vlans" {
  value = {
    private    = equinix_metal_vlan.private.vxlan
    management = equinix_metal_vlan.management.vxlan
  }
}

output "ssh_commands" {
  value = [for s in equinix_metal_device.pop_server : "ssh root@${s.access_public_ipv4}"]
}
