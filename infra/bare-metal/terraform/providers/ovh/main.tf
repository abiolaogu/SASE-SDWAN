# OpenSASE Bare Metal Orchestrator - OVH Module
# Dedicated Servers with High-Speed NICs

terraform {
  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 0.36"
    }
  }
}

# ===========================================
# Variables
# ===========================================

variable "pop_name" {
  type = string
}

variable "datacenter" {
  description = "OVH datacenter (rbx, sbg, gra, bhs, waw)"
  type        = string
  default     = "rbx"
}

variable "plan" {
  description = "Server plan (HGR-HCI-2, ADVANCE-6)"
  type        = string
  default     = "ADVANCE-6"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "ssh_public_key" {
  type = string
}

variable "controller_url" {
  type    = string
  default = "https://manage.opensase.io"
}

variable "activation_key" {
  type      = string
  sensitive = true
}

variable "vrack_id" {
  description = "OVH vRack ID for private networking"
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
  server_specs = {
    "HGR-HCI-2" = {
      cores    = 48
      ram_gb   = 512
      nic_type = "intel_xxv710"
      speed    = 50
    }
    "ADVANCE-6" = {
      cores    = 64
      ram_gb   = 512
      nic_type = "intel_xxv710"
      speed    = 70
    }
  }
  
  spec = local.server_specs[var.plan]
  
  # Datacenter mapping
  dc_regions = {
    "rbx" = "eu-west-rbx"
    "sbg" = "eu-west-sbg"
    "gra" = "eu-west-gra"
    "bhs" = "ca-east-bhs"
    "waw" = "eu-central-waw"
    "sgp" = "ap-southeast-sgp"
    "syd" = "ap-southeast-syd"
  }
}

# ===========================================
# SSH Key
# ===========================================

resource "ovh_me_ssh_key" "obmo" {
  key_name = "obmo-${var.pop_name}"
  key      = var.ssh_public_key
}

# ===========================================
# Dedicated Servers
# ===========================================

resource "ovh_dedicated_server_install_task" "server" {
  count = var.instance_count
  
  service_name = ovh_dedicated_server.server[count.index].service_name
  
  details {
    custom_hostname = "obmo-${var.pop_name}-${format("%02d", count.index + 1)}"
  }
  
  template_name = "ubuntu2204-server_64"
  
  user_metadata {
    key   = "ssh_keys"
    value = jsonencode([var.ssh_public_key])
  }
}

resource "ovh_dedicated_server" "server" {
  count = var.instance_count
  
  # Note: OVH dedicated servers require ordering through API
  # This resource assumes servers are pre-ordered
  
  # Service name from order
  # service_name = var.service_names[count.index]
}

# Note: OVH dedicated server provisioning typically requires:
# 1. Order server via OVH API /order/cart endpoint
# 2. Wait for provisioning
# 3. Install OS via install_task
# 
# For automation, use null_resource with OVH API:

resource "null_resource" "provision_server" {
  count = var.instance_count
  
  provisioner "local-exec" {
    command = <<-EOF
      # OVH API automation script
      curl -X POST "https://eu.api.ovh.com/1.0/order/cart" \
        -H "X-Ovh-Application: $OVH_APPLICATION_KEY" \
        -H "X-Ovh-Timestamp: $(date +%s)" \
        -H "X-Ovh-Signature: $OVH_SIGNATURE" \
        -H "X-Ovh-Consumer: $OVH_CONSUMER_KEY" \
        -d '{
          "ovhSubsidiary": "EU",
          "description": "OBMO ${var.pop_name} Server ${count.index + 1}"
        }'
    EOF
  }
}

# ===========================================
# vRack Private Network
# ===========================================

resource "ovh_vrack_dedicated_server" "server" {
  count = var.vrack_id != "" ? var.instance_count : 0
  
  vrack_id     = var.vrack_id
  # server_id from provisioned server
}

# ===========================================
# IP Block for Anycast
# ===========================================

resource "ovh_ip_service" "anycast" {
  # Order additional IP block
  # ovh_subsidiary = "EU"
  # type = "failover"
}

# ===========================================
# Ansible Inventory Generation
# ===========================================

resource "local_file" "inventory" {
  filename = "${path.module}/../../../ansible/inventory/ovh-${var.pop_name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        ovh_servers = {
          hosts = {}  # Populated after provisioning
          vars = {
            ansible_user = "root"
            pop_name     = var.pop_name
            provider     = "ovh"
            nic_type     = local.spec.nic_type
            nic_speed    = local.spec.speed
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
    name       = var.pop_name
    datacenter = var.datacenter
    plan       = var.plan
    nic_type   = local.spec.nic_type
    speed_gbps = local.spec.speed
  }
}

output "inventory_path" {
  value = local_file.inventory.filename
}
