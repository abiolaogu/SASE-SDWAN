# OpenSASE Bare Metal Orchestrator - Leaseweb Module
# Bare Metal Servers via REST API

terraform {
  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 1.18"
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
  description = "Leaseweb datacenter (AMS-01, FRA-10, SFO-12)"
  type        = string
  default     = "AMS-01"
}

variable "server_type" {
  description = "Server configuration"
  type        = string
  default     = "BARE_METAL_XL"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "ssh_public_key" {
  type = string
}

variable "api_key" {
  type      = string
  sensitive = true
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
  server_specs = {
    "BARE_METAL_XL" = {
      cores    = 48
      ram_gb   = 256
      storage  = "4x 1.92TB NVMe"
      nic_type = "mellanox_cx5"
      speed    = 120
    }
    "BARE_METAL_L" = {
      cores    = 32
      ram_gb   = 128
      storage  = "2x 960GB NVMe"
      nic_type = "intel_xxv710"
      speed    = 50
    }
  }
  
  spec = local.server_specs[var.server_type]
  
  dc_regions = {
    "AMS-01" = "eu-west"
    "FRA-10" = "eu-central"
    "WDC-01" = "us-east"
    "SFO-12" = "us-west"
    "SIN-01" = "ap-southeast"
  }
}

# ===========================================
# Leaseweb API - Order Server
# ===========================================

resource "restapi_object" "server" {
  count = var.instance_count
  
  path         = "/bareMetals/v2/servers"
  create_path  = "/bareMetals/v2/servers"
  destroy_path = "/bareMetals/v2/servers/{id}"
  
  data = jsonencode({
    reference       = "obmo-${var.pop_name}-${format("%02d", count.index + 1)}"
    dataCenter      = var.datacenter
    serverType      = var.server_type
    operatingSystem = "UBUNTU_22_04_64BIT"
    sshKeys         = [var.ssh_public_key]
    autoInstall     = true
    metadata = {
      pop_name = var.pop_name
      index    = count.index + 1
      obmo     = true
    }
  })
}

# ===========================================
# Leaseweb API - Private Network
# ===========================================

resource "restapi_object" "private_network" {
  path         = "/bareMetals/v2/privateNetworks"
  create_path  = "/bareMetals/v2/privateNetworks"
  destroy_path = "/bareMetals/v2/privateNetworks/{id}"
  
  data = jsonencode({
    name        = "obmo-${var.pop_name}-private"
    dataCenter  = var.datacenter
    dhcp        = false
    ipRange     = "10.100.0.0/24"
  })
}

# ===========================================
# Leaseweb API - IP Configuration
# ===========================================

resource "restapi_object" "failover_ip" {
  count = var.instance_count > 0 ? 1 : 0
  
  path         = "/bareMetals/v2/ips"
  create_path  = "/bareMetals/v2/ips"
  destroy_path = "/bareMetals/v2/ips/{id}"
  
  data = jsonencode({
    serverId = restapi_object.server[0].id
    type     = "FAILOVER"
    quantity = 4
  })
}

# ===========================================
# Configure Servers via SSH
# ===========================================

resource "null_resource" "configure" {
  count = var.instance_count
  
  depends_on = [restapi_object.server]
  
  triggers = {
    server_id = restapi_object.server[count.index].id
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      # Wait for server to be ready
      sleep 300
      
      # Get server IP from Leaseweb API
      SERVER_IP=$(curl -s -H "X-Lsw-Auth: ${var.api_key}" \
        "https://api.leaseweb.com/bareMetals/v2/servers/${restapi_object.server[count.index].id}" | \
        jq -r '.networkInterfaces[0].ip')
      
      if [ -n "$SERVER_IP" ] && [ "$SERVER_IP" != "null" ]; then
        echo "Configuring server at $SERVER_IP"
        
        ssh -o StrictHostKeyChecking=no root@$SERVER_IP << 'SSHEOF'
          # Basic setup
          apt-get update && apt-get upgrade -y
          
          # Configure sysctl
          cat >> /etc/sysctl.conf << 'SYSCTL'
net.core.rmem_max = 536870912
net.core.wmem_max = 536870912
net.ipv4.ip_forward = 1
vm.nr_hugepages = 8192
SYSCTL
          sysctl -p
          
          # Install VPP
          curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
          apt-get install -y vpp vpp-plugin-core vpp-plugin-dpdk vpp-plugin-wireguard
          
          # Install FlexiEdge
          curl -sL https://deb.flexiwan.com/setup | bash
          apt-get install -y flexiwan-router
          
          echo "Server configuration complete"
SSHEOF
      fi
    EOF
  }
}

# ===========================================
# Ansible Inventory
# ===========================================

resource "local_file" "inventory" {
  filename = "${path.module}/../../../ansible/inventory/leaseweb-${var.pop_name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        leaseweb_servers = {
          hosts = {}
          vars = {
            ansible_user   = "root"
            pop_name       = var.pop_name
            provider       = "leaseweb"
            nic_type       = local.spec.nic_type
            nic_speed      = local.spec.speed
            controller_url = var.controller_url
            activation_key = var.activation_key
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
    name        = var.pop_name
    datacenter  = var.datacenter
    server_type = var.server_type
    nic_type    = local.spec.nic_type
    speed_gbps  = local.spec.speed
  }
}

output "server_ids" {
  value = [for s in restapi_object.server : s.id]
}

output "private_network_id" {
  value = restapi_object.private_network.id
}
