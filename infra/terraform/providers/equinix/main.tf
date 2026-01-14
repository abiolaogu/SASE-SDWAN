# Equinix Metal Provider Configuration
# Bare metal servers for high-performance PoPs

terraform {
  required_providers {
    equinix = {
      source  = "equinix/equinix"
      version = "~> 1.20"
    }
  }
}

provider "equinix" {
  auth_token = var.equinix_auth_token
}

# ===========================================
# Variables
# ===========================================

variable "equinix_auth_token" {
  description = "Equinix Metal auth token"
  type        = string
  sensitive   = true
}

variable "pop_name" {
  type = string
}

variable "metro" {
  description = "Equinix metro code (am, ny, sv, etc.)"
  type        = string
}

variable "plan" {
  description = "Server plan"
  type        = string
  default     = "c3.medium.x86"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "ssh_public_key" {
  type = string
}

variable "user_data" {
  type = string
}

variable "tags" {
  type = map(string)
}

# ===========================================
# Metro/Location Mapping
# ===========================================

locals {
  metro_map = {
    "nyc" = "ny"
    "ldn" = "ld"
    "fra" = "fr"
    "ams" = "am"
    "tok" = "ty"
    "syd" = "sy"
    "sin" = "sg"
    "sjc" = "sv"
    "lax" = "la"
    "chi" = "ch"
  }
  
  actual_metro = lookup(local.metro_map, var.metro, var.metro)
}

# ===========================================
# Project
# ===========================================

resource "equinix_metal_project" "pop" {
  name = "opensase-${var.pop_name}"
}

# ===========================================
# SSH Key
# ===========================================

resource "equinix_metal_project_ssh_key" "pop" {
  name       = "opensase-${var.pop_name}"
  public_key = var.ssh_public_key
  project_id = equinix_metal_project.pop.id
}

# ===========================================
# VLAN for PoP
# ===========================================

resource "equinix_metal_vlan" "pop" {
  project_id  = equinix_metal_project.pop.id
  metro       = local.actual_metro
  description = "OpenSASE ${var.pop_name} internal network"
}

# ===========================================
# Bare Metal Servers
# ===========================================

resource "equinix_metal_device" "pop" {
  count = var.instance_count
  
  hostname         = "opensase-${var.pop_name}-${count.index + 1}"
  plan             = var.plan
  metro            = local.actual_metro
  operating_system = "ubuntu_22_04"
  billing_cycle    = "hourly"
  project_id       = equinix_metal_project.pop.id
  
  project_ssh_key_ids = [equinix_metal_project_ssh_key.pop.id]
  
  user_data = var.user_data
  
  tags = [for k, v in var.tags : "${k}:${v}"]
  
  # Wait for provisioning
  wait_for_reservation_deprovision = true
  
  # IP settings
  ip_address {
    type = "public_ipv4"
  }
  
  ip_address {
    type = "private_ipv4"
  }
  
  ip_address {
    type = "public_ipv6"
  }
}

# ===========================================
# Attach VLAN to devices
# ===========================================

resource "equinix_metal_port_vlan_attachment" "pop" {
  count = var.instance_count
  
  device_id = equinix_metal_device.pop[count.index].id
  port_name = "bond0"
  vlan_vnid = equinix_metal_vlan.pop.vxlan
}

# ===========================================
# Outputs
# ===========================================

output "public_ips" {
  value = [for d in equinix_metal_device.pop : d.access_public_ipv4]
}

output "private_ips" {
  value = [for d in equinix_metal_device.pop : d.access_private_ipv4]
}

output "instance_ids" {
  value = [for d in equinix_metal_device.pop : d.id]
}

output "project_id" {
  value = equinix_metal_project.pop.id
}

output "vlan_id" {
  value = equinix_metal_vlan.pop.id
}
