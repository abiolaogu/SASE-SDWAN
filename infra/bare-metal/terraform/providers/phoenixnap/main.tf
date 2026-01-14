# OpenSASE Bare Metal Orchestrator - PhoenixNAP Module
# BMC (Bare Metal Cloud) via REST API

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

variable "location" {
  description = "PhoenixNAP location (PHX, ASH, SGP, NLD, CHI)"
  type        = string
  default     = "PHX"
}

variable "server_type" {
  description = "Server type (s2.c1.xlarge, d2.c3.xlarge)"
  type        = string
  default     = "d2.c3.xlarge"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "ssh_public_key" {
  type = string
}

variable "client_id" {
  type      = string
  sensitive = true
}

variable "client_secret" {
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
    "s2.c1.xlarge" = {
      cores      = 40
      ram_gb     = 256
      nic_type   = "intel_xxv710"
      speed      = 100
      price_hour = 3.28
    }
    "d2.c3.xlarge" = {
      cores      = 64
      ram_gb     = 512
      nic_type   = "mellanox_cx5"
      speed      = 200
      price_hour = 5.50
    }
    "d2.c4.xlarge" = {
      cores      = 96
      ram_gb     = 768
      nic_type   = "mellanox_cx6"
      speed      = 200
      price_hour = 7.80
    }
  }
  
  spec = local.server_specs[var.server_type]
}

# ===========================================
# OAuth Token
# ===========================================

data "http" "auth_token" {
  url    = "https://auth.phoenixnap.com/auth/realms/BMC/protocol/openid-connect/token"
  method = "POST"
  
  request_headers = {
    Content-Type = "application/x-www-form-urlencoded"
  }
  
  request_body = "grant_type=client_credentials&client_id=${var.client_id}&client_secret=${var.client_secret}"
}

locals {
  access_token = jsondecode(data.http.auth_token.response_body).access_token
}

# ===========================================
# SSH Key
# ===========================================

resource "restapi_object" "ssh_key" {
  path         = "/bmc/v1/ssh-keys"
  create_path  = "/bmc/v1/ssh-keys"
  destroy_path = "/bmc/v1/ssh-keys/{id}"
  
  data = jsonencode({
    default = true
    name    = "obmo-${var.pop_name}"
    key     = var.ssh_public_key
  })
}

# ===========================================
# Private Network
# ===========================================

resource "restapi_object" "private_network" {
  path         = "/networks/v1/private-networks"
  create_path  = "/networks/v1/private-networks"
  destroy_path = "/networks/v1/private-networks/{id}"
  
  data = jsonencode({
    name          = "obmo-${var.pop_name}-private"
    location      = var.location
    locationDefault = true
    cidr          = "10.100.0.0/24"
  })
}

# ===========================================
# Bare Metal Servers
# ===========================================

resource "restapi_object" "server" {
  count = var.instance_count
  
  path         = "/bmc/v1/servers"
  create_path  = "/bmc/v1/servers"
  destroy_path = "/bmc/v1/servers/{id}"
  
  data = jsonencode({
    hostname        = "obmo-${var.pop_name}-${format("%02d", count.index + 1)}"
    description     = "OpenSASE OBMO ${var.pop_name} Server ${count.index + 1}"
    os              = "ubuntu/jammy"
    type            = var.server_type
    location        = var.location
    sshKeys         = [restapi_object.ssh_key.id]
    sshKeyIds       = [restapi_object.ssh_key.id]
    networkType     = "PRIVATE_AND_PUBLIC"
    
    installDefaultSshKeys = true
    
    networkConfiguration = {
      privateNetworkConfiguration = {
        configurationType = "USER_DEFINED"
        privateNetworks = [
          {
            id   = restapi_object.private_network.id
            dhcp = false
            ips  = ["10.100.0.${10 + count.index}"]
          }
        ]
      }
    }
    
    tags = [
      {
        name  = "environment"
        value = var.environment
      },
      {
        name  = "pop"
        value = var.pop_name
      },
      {
        name  = "obmo"
        value = "true"
      }
    ]
  })
}

# ===========================================
# Public IP Blocks
# ===========================================

resource "restapi_object" "ip_block" {
  count = var.instance_count > 0 ? 1 : 0
  
  path         = "/ips/v1/ip-blocks"
  create_path  = "/ips/v1/ip-blocks"
  destroy_path = "/ips/v1/ip-blocks/{id}"
  
  data = jsonencode({
    location    = var.location
    cidrBlockSize = "/29"
    description = "OBMO ${var.pop_name} anycast IPs"
    tags = [
      {
        name  = "pop"
        value = var.pop_name
      }
    ]
  })
}

# ===========================================
# Configure Servers
# ===========================================

resource "null_resource" "configure" {
  count = var.instance_count
  
  depends_on = [restapi_object.server]
  
  triggers = {
    server_id = restapi_object.server[count.index].id
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      # Wait for server provisioning
      sleep 180
      
      # Get server IP
      SERVER_IP=$(curl -s -H "Authorization: Bearer ${local.access_token}" \
        "https://api.phoenixnap.com/bmc/v1/servers/${restapi_object.server[count.index].id}" | \
        jq -r '.publicIpAddresses[0]')
      
      if [ -n "$SERVER_IP" ] && [ "$SERVER_IP" != "null" ]; then
        echo "Configuring PhoenixNAP server at $SERVER_IP"
        
        # Run Ansible
        ansible-playbook \
          -i "$SERVER_IP," \
          -u ubuntu \
          --become \
          "${path.module}/../../../ansible/playbooks/bare-metal-setup.yml" \
          -e "pop_name=${var.pop_name}" \
          -e "server_index=${count.index + 1}" \
          -e "nic_type=${local.spec.nic_type}" \
          -e "nic_speed=${local.spec.speed}" \
          -e "controller_url=${var.controller_url}" \
          -e "activation_key=${var.activation_key}"
      fi
    EOF
  }
}

# ===========================================
# Ansible Inventory
# ===========================================

resource "local_file" "inventory" {
  filename = "${path.module}/../../../ansible/inventory/phoenixnap-${var.pop_name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        phoenixnap_servers = {
          hosts = {}
          vars = {
            ansible_user   = "ubuntu"
            ansible_become = true
            pop_name       = var.pop_name
            provider       = "phoenixnap"
            nic_type       = local.spec.nic_type
            nic_speed      = local.spec.speed
            controller_url = var.controller_url
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
    location    = var.location
    server_type = var.server_type
    nic_type    = local.spec.nic_type
    speed_gbps  = local.spec.speed
    price_hour  = local.spec.price_hour
  }
}

output "server_ids" {
  value = [for s in restapi_object.server : s.id]
}

output "private_network_id" {
  value = restapi_object.private_network.id
}

output "ip_block_id" {
  value = length(restapi_object.ip_block) > 0 ? restapi_object.ip_block[0].id : null
}
