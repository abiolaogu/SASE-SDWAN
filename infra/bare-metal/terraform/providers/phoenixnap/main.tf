# OBMO PhoenixNAP Module (TIER 2 - NA BARE METAL CLOUD)
# BMC API for bare metal servers

terraform {
  required_providers {
    pnap = {
      source  = "phoenixnap/pnap"
      version = "~> 0.18"
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
    location       = string  # PHX, ASH, CHI, SEA
    environment    = string
    controller_url = string
    activation_key = string
    network_id     = number
  })
}

variable "high_performance" {
  description = "Use 100G capable servers"
  type        = bool
  default     = true
}

variable "enable_ha" {
  description = "Enable HA with secondary server"
  type        = bool
  default     = false
}

variable "ssh_public_key" {
  type = string
}

# ===========================================
# Locals
# ===========================================

locals {
  # PhoenixNAP server types
  # s2.c1.medium: 16 cores, 64GB RAM, 2x10GbE
  # s2.c1.large: 32 cores, 256GB RAM, 2x25GbE
  # s2.c2.medium: 64 cores, 512GB RAM, 2x100GbE
  server_type = var.high_performance ? "s2.c2.medium" : "s2.c1.large"
  
  nic_info = {
    "s2.c2.medium" = { type = "mellanox_cx5", speed = 200 }
    "s2.c1.large"  = { type = "intel_xxv710", speed = 50 }
    "s2.c1.medium" = { type = "intel_x710", speed = 20 }
  }
  
  instance_count = var.enable_ha ? 2 : 1
}

# ===========================================
# SSH Key
# ===========================================

resource "pnap_ssh_key" "opensase" {
  name = "opensase-${var.pop_config.name}"
  key  = var.ssh_public_key
}

# ===========================================
# Private Network
# ===========================================

resource "pnap_private_network" "pop_network" {
  name        = "opensase-${var.pop_config.name}-net"
  location    = var.pop_config.location
  cidr        = "10.${var.pop_config.network_id}.0.0/24"
  description = "OpenSASE Private Network - ${var.pop_config.name}"
}

# ===========================================
# Primary Bare Metal Server
# ===========================================

resource "pnap_server" "pop_primary" {
  hostname = "opensase-${var.pop_config.name}-01"
  os       = "ubuntu/jammy"
  type     = local.server_type
  location = var.pop_config.location
  
  ssh_keys                 = [pnap_ssh_key.opensase.id]
  install_default_ssh_keys = false
  
  network_type = "PUBLIC_AND_PRIVATE"
  
  cloud_init {
    user_data = base64encode(templatefile("${path.module}/templates/cloud-init.yaml.tpl", {
      pop_name       = var.pop_config.name
      role           = "primary"
      controller_url = var.pop_config.controller_url
      activation_key = var.pop_config.activation_key
      nic_type       = local.nic_info[local.server_type].type
      nic_speed      = local.nic_info[local.server_type].speed
    }))
  }
  
  tags {
    name  = "env"
    value = var.pop_config.environment
  }
  
  tags {
    name  = "pop"
    value = var.pop_config.name
  }
  
  tags {
    name  = "role"
    value = "primary"
  }
}

# ===========================================
# Secondary Server for HA
# ===========================================

resource "pnap_server" "pop_secondary" {
  count = var.enable_ha ? 1 : 0
  
  hostname = "opensase-${var.pop_config.name}-02"
  os       = "ubuntu/jammy"
  type     = local.server_type
  location = var.pop_config.location
  
  ssh_keys                 = [pnap_ssh_key.opensase.id]
  install_default_ssh_keys = false
  
  network_type = "PUBLIC_AND_PRIVATE"
  
  cloud_init {
    user_data = base64encode(templatefile("${path.module}/templates/cloud-init.yaml.tpl", {
      pop_name       = var.pop_config.name
      role           = "secondary"
      controller_url = var.pop_config.controller_url
      activation_key = var.pop_config.activation_key
      nic_type       = local.nic_info[local.server_type].type
      nic_speed      = local.nic_info[local.server_type].speed
    }))
  }
  
  tags {
    name  = "env"
    value = var.pop_config.environment
  }
  
  tags {
    name  = "pop"
    value = var.pop_config.name
  }
  
  tags {
    name  = "role"
    value = "secondary"
  }
}

# ===========================================
# Attach Servers to Private Network
# ===========================================

resource "pnap_server_private_network" "primary" {
  server_id = pnap_server.pop_primary.id
  id        = pnap_private_network.pop_network.id
  ips       = ["10.${var.pop_config.network_id}.0.10"]
}

resource "pnap_server_private_network" "secondary" {
  count = var.enable_ha ? 1 : 0
  
  server_id = pnap_server.pop_secondary[0].id
  id        = pnap_private_network.pop_network.id
  ips       = ["10.${var.pop_config.network_id}.0.11"]
}

# ===========================================
# IP Block for Anycast
# ===========================================

resource "pnap_ip_block" "anycast" {
  location        = var.pop_config.location
  cidr_block_size = "/29"
  description     = "OpenSASE Anycast IPs - ${var.pop_config.name}"
}

# ===========================================
# Ansible Inventory
# ===========================================

resource "local_file" "inventory" {
  filename = "${path.module}/../../../ansible/inventory/phoenixnap-${var.pop_config.name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        phoenixnap_servers = {
          hosts = merge(
            {
              "opensase-${var.pop_config.name}-01" = {
                ansible_host = pnap_server.pop_primary.public_ip_addresses[0]
                private_ip   = "10.${var.pop_config.network_id}.0.10"
                role         = "primary"
              }
            },
            var.enable_ha ? {
              "opensase-${var.pop_config.name}-02" = {
                ansible_host = pnap_server.pop_secondary[0].public_ip_addresses[0]
                private_ip   = "10.${var.pop_config.network_id}.0.11"
                role         = "secondary"
              }
            } : {}
          )
          vars = {
            ansible_user   = "ubuntu"
            ansible_become = true
            pop_name       = var.pop_config.name
            provider       = "phoenixnap"
            nic_type       = local.nic_info[local.server_type].type
            nic_speed      = local.nic_info[local.server_type].speed
            controller_url = var.pop_config.controller_url
            anycast_cidr   = pnap_ip_block.anycast.cidr
          }
        }
      }
    }
  })
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  value = {
    pop_name     = var.pop_config.name
    location     = var.pop_config.location
    server_type  = local.server_type
    nic_type     = local.nic_info[local.server_type].type
    nic_speed    = local.nic_info[local.server_type].speed
    primary_ip   = pnap_server.pop_primary.public_ip_addresses[0]
    secondary_ip = var.enable_ha ? pnap_server.pop_secondary[0].public_ip_addresses[0] : null
    anycast_cidr = pnap_ip_block.anycast.cidr
  }
}

output "public_ips" {
  value = concat(
    pnap_server.pop_primary.public_ip_addresses,
    var.enable_ha ? pnap_server.pop_secondary[0].public_ip_addresses : []
  )
}

output "private_ips" {
  value = concat(
    ["10.${var.pop_config.network_id}.0.10"],
    var.enable_ha ? ["10.${var.pop_config.network_id}.0.11"] : []
  )
}

output "server_ids" {
  value = concat(
    [pnap_server.pop_primary.id],
    var.enable_ha ? [pnap_server.pop_secondary[0].id] : []
  )
}

output "anycast_cidr" {
  value = pnap_ip_block.anycast.cidr
}

output "private_network_id" {
  value = pnap_private_network.pop_network.id
}
