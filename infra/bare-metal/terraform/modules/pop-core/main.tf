# OpenSASE Bare Metal Orchestrator - Pop Core Module
# Provider-agnostic PoP logic for all bare metal providers

# ===========================================
# Variables (Provider-Agnostic)
# ===========================================

variable "pop_name" {
  description = "PoP identifier (e.g., nyc1, lon1, fra1)"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,15}$", var.pop_name))
    error_message = "PoP name must be lowercase alphanumeric, 3-16 chars"
  }
}

variable "provider_type" {
  description = "Bare metal provider"
  type        = string
  
  validation {
    condition = contains([
      "equinix", "ovh", "hetzner", "scaleway",
      "leaseweb", "phoenixnap", "voxility",
      "serverhub", "reliablesite"
    ], var.provider_type)
    error_message = "Must be a supported bare metal provider"
  }
}

variable "region" {
  description = "Provider-specific region code"
  type        = string
}

variable "server_plan" {
  description = "Server plan/type"
  type        = string
}

variable "instance_count" {
  description = "Number of servers in PoP"
  type        = number
  default     = 2
}

variable "public_ips" {
  description = "Public IPs from provider module"
  type        = list(string)
}

variable "private_ips" {
  description = "Private IPs from provider module"
  type        = list(string)
  default     = []
}

variable "ssh_user" {
  description = "SSH user for servers"
  type        = string
  default     = "root"
}

variable "ssh_private_key_path" {
  description = "Path to SSH private key"
  type        = string
  default     = "~/.ssh/opensase"
}

# ===========================================
# FlexiWAN Configuration
# ===========================================

variable "flexiwan_url" {
  description = "FlexiWAN management URL"
  type        = string
  default     = "https://manage.opensase.io"
}

variable "flexiwan_token" {
  description = "FlexiWAN device token"
  type        = string
  sensitive   = true
}

# ===========================================
# Network Configuration
# ===========================================

variable "nic_type" {
  description = "NIC type (mellanox_cx5, intel_xxv710, etc)"
  type        = string
}

variable "nic_speed_gbps" {
  description = "NIC speed in Gbps"
  type        = number
}

variable "enable_bgp" {
  description = "Enable BGP for anycast"
  type        = bool
  default     = true
}

variable "bgp_asn" {
  description = "BGP AS number"
  type        = number
  default     = 65100
}

variable "anycast_prefixes" {
  description = "Anycast IPv4 prefixes to announce"
  type        = list(string)
  default     = []
}

# ===========================================
# Environment
# ===========================================

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be production, staging, or development"
  }
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
  common_tags = merge(var.tags, {
    pop         = var.pop_name
    provider    = var.provider_type
    environment = var.environment
    managed_by  = "obmo"
  })
  
  # VPP configuration based on NIC speed
  vpp_config = {
    worker_cores = var.nic_speed_gbps >= 100 ? 16 : (var.nic_speed_gbps >= 50 ? 8 : 4)
    rx_queues    = var.nic_speed_gbps >= 100 ? 16 : (var.nic_speed_gbps >= 50 ? 8 : 4)
    tx_queues    = var.nic_speed_gbps >= 100 ? 16 : (var.nic_speed_gbps >= 50 ? 8 : 4)
    rx_desc      = var.nic_speed_gbps >= 100 ? 8192 : 4096
    tx_desc      = var.nic_speed_gbps >= 100 ? 8192 : 4096
    buffers      = var.nic_speed_gbps >= 100 ? 524288 : 256000
    hugepages_gb = var.nic_speed_gbps >= 100 ? 16 : 8
  }
  
  # DPDK driver selection
  dpdk_driver = (
    can(regex("mellanox", var.nic_type)) ? "mlx5_core" :
    can(regex("intel_e810", var.nic_type)) ? "ice" :
    "i40e"
  )
}

# ===========================================
# Cloud-Init Generation
# ===========================================

resource "local_file" "cloud_init" {
  count = var.instance_count
  
  filename = "${path.module}/generated/${var.pop_name}-${count.index + 1}-cloud-init.yaml"
  
  content = templatefile("${path.module}/templates/cloud-init.yaml.tpl", {
    pop_name       = var.pop_name
    server_index   = count.index + 1
    server_count   = var.instance_count
    provider_type  = var.provider_type
    flexiwan_url   = var.flexiwan_url
    flexiwan_token = var.flexiwan_token
    nic_type       = var.nic_type
    nic_speed      = var.nic_speed_gbps
    vpp_config     = local.vpp_config
    dpdk_driver    = local.dpdk_driver
    enable_bgp     = var.enable_bgp
    bgp_asn        = var.bgp_asn
    is_primary     = count.index == 0
  })
}

# ===========================================
# Ansible Inventory Generation
# ===========================================

resource "local_file" "ansible_inventory" {
  filename = "${path.module}/../../ansible/inventory/${var.pop_name}.yml"
  
  content = templatefile("${path.module}/templates/ansible-inventory.tpl", {
    pop_name           = var.pop_name
    provider_type      = var.provider_type
    environment        = var.environment
    ssh_user           = var.ssh_user
    ssh_key_path       = var.ssh_private_key_path
    flexiwan_url       = var.flexiwan_url
    flexiwan_token     = var.flexiwan_token
    nic_type           = var.nic_type
    nic_speed          = var.nic_speed_gbps
    enable_bgp         = var.enable_bgp
    bgp_asn            = var.bgp_asn
    anycast_prefixes   = var.anycast_prefixes
    vpp_config         = local.vpp_config
    servers = [
      for i, ip in var.public_ips : {
        name       = "obmo-${var.pop_name}-${format("%02d", i + 1)}"
        public_ip  = ip
        private_ip = length(var.private_ips) > i ? var.private_ips[i] : ""
        is_primary = i == 0
      }
    ]
  })
}

# ===========================================
# Health Check Endpoints
# ===========================================

resource "null_resource" "health_check" {
  count = var.instance_count
  
  triggers = {
    ip = var.public_ips[count.index]
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      for i in {1..30}; do
        if curl -sf "http://${var.public_ips[count.index]}:8080/health" > /dev/null; then
          echo "Health check passed for ${var.pop_name}-${count.index + 1}"
          exit 0
        fi
        sleep 10
      done
      echo "Health check failed for ${var.pop_name}-${count.index + 1}"
      exit 1
    EOF
  }
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  description = "PoP deployment information"
  value = {
    name        = var.pop_name
    provider    = var.provider_type
    region      = var.region
    plan        = var.server_plan
    environment = var.environment
    instances   = var.instance_count
  }
}

output "network_info" {
  description = "Network configuration"
  value = {
    nic_type   = var.nic_type
    nic_speed  = var.nic_speed_gbps
    bgp_asn    = var.enable_bgp ? var.bgp_asn : null
    anycast    = var.anycast_prefixes
  }
}

output "vpp_config" {
  description = "VPP configuration for this PoP"
  value       = local.vpp_config
}

output "servers" {
  description = "Server details"
  value = [
    for i, ip in var.public_ips : {
      name       = "obmo-${var.pop_name}-${format("%02d", i + 1)}"
      public_ip  = ip
      private_ip = length(var.private_ips) > i ? var.private_ips[i] : null
      ssh        = "ssh ${var.ssh_user}@${ip}"
      health     = "http://${ip}:8080/health"
    }
  ]
}

output "ansible_inventory_path" {
  description = "Path to generated Ansible inventory"
  value       = local_file.ansible_inventory.filename
}
