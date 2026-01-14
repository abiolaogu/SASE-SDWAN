# OpenSASE Bare Metal Orchestrator - Hetzner Module
# AX-Series Dedicated Servers via Robot API

terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.44"
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
  description = "Hetzner datacenter (fsn1, nbg1, hel1, ash)"
  type        = string
  default     = "fsn1"
}

variable "server_type" {
  description = "Dedicated server type (AX101, AX161, etc)"
  type        = string
  default     = "AX161"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "ssh_public_key" {
  type = string
}

variable "robot_user" {
  description = "Hetzner Robot API username"
  type        = string
  sensitive   = true
}

variable "robot_password" {
  description = "Hetzner Robot API password"
  type        = string
  sensitive   = true
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
    "AX41" = {
      cores    = 6
      ram_gb   = 64
      nic_type = "intel_x710"
      speed    = 10
      price    = 49
    }
    "AX51" = {
      cores    = 8
      ram_gb   = 64
      nic_type = "intel_x710"
      speed    = 10
      price    = 64
    }
    "AX101" = {
      cores    = 24
      ram_gb   = 128
      nic_type = "intel_x710"
      speed    = 20
      price    = 99
    }
    "AX161" = {
      cores    = 64
      ram_gb   = 128
      nic_type = "intel_x710"
      speed    = 20
      price    = 176
    }
    "AX102" = {
      cores    = 32
      ram_gb   = 128
      nic_type = "intel_x710"
      speed    = 20
      price    = 114
    }
  }
  
  spec = local.server_specs[var.server_type]
  
  dc_mapping = {
    "fsn1" = "FSN1-DC14"
    "nbg1" = "NBG1-DC3"
    "hel1" = "HEL1-DC2"
    "ash"  = "ASH-DC1"
  }
}

# ===========================================
# SSH Key
# ===========================================

resource "hcloud_ssh_key" "obmo" {
  name       = "obmo-${var.pop_name}"
  public_key = var.ssh_public_key
}

# ===========================================
# Hetzner Robot API for Dedicated Servers
# ===========================================

# Hetzner dedicated servers require Robot API
# Using null_resource with local-exec

resource "null_resource" "order_server" {
  count = var.instance_count
  
  triggers = {
    pop_name = var.pop_name
    index    = count.index
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      #!/bin/bash
      # Hetzner Robot API - Order dedicated server
      
      ROBOT_USER="${var.robot_user}"
      ROBOT_PASS="${var.robot_password}"
      
      # Search for available server
      AVAILABLE=$(curl -s -u "$ROBOT_USER:$ROBOT_PASS" \
        "https://robot-ws.your-server.de/order/server/product" | \
        jq -r '.[] | select(.name == "${var.server_type}") | .id')
      
      if [ -n "$AVAILABLE" ]; then
        echo "Found available ${var.server_type} server"
        
        # Order the server
        curl -s -u "$ROBOT_USER:$ROBOT_PASS" \
          -X POST "https://robot-ws.your-server.de/order/server/transaction" \
          -d "product_id=$AVAILABLE" \
          -d "location=${local.dc_mapping[var.datacenter]}" \
          -d "ssh_key=${var.ssh_public_key}" \
          -d "comment=OBMO ${var.pop_name} Server ${count.index + 1}"
      fi
    EOF
  }
}

# ===========================================
# Server Configuration via Robot API
# ===========================================

resource "null_resource" "configure_server" {
  count = var.instance_count
  
  depends_on = [null_resource.order_server]
  
  triggers = {
    config_hash = sha256(templatefile("${path.module}/templates/bootstrap.sh.tpl", {
      pop_name       = var.pop_name
      server_index   = count.index + 1
      controller_url = var.controller_url
      activation_key = var.activation_key
      nic_type       = local.spec.nic_type
      nic_speed      = local.spec.speed
    }))
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      #!/bin/bash
      # Wait for server to be ready and configure
      
      ROBOT_USER="${var.robot_user}"
      ROBOT_PASS="${var.robot_password}"
      
      # Get server IP from Robot API
      SERVER_IP=$(curl -s -u "$ROBOT_USER:$ROBOT_PASS" \
        "https://robot-ws.your-server.de/server" | \
        jq -r '.[] | select(.server.server_name | contains("${var.pop_name}")) | .server.server_ip' | \
        head -1)
      
      if [ -n "$SERVER_IP" ]; then
        echo "Configuring server at $SERVER_IP"
        
        # Run Ansible playbook
        ansible-playbook \
          -i "$SERVER_IP," \
          -u root \
          "${path.module}/../../../ansible/playbooks/bare-metal-setup.yml" \
          -e "pop_name=${var.pop_name}" \
          -e "server_index=${count.index + 1}" \
          -e "nic_type=${local.spec.nic_type}" \
          -e "nic_speed=${local.spec.speed}"
      fi
    EOF
  }
}

# ===========================================
# vSwitch for Private Networking
# ===========================================

resource "null_resource" "vswitch" {
  depends_on = [null_resource.order_server]
  
  provisioner "local-exec" {
    command = <<-EOF
      #!/bin/bash
      ROBOT_USER="${var.robot_user}"
      ROBOT_PASS="${var.robot_password}"
      
      # Create vSwitch
      curl -s -u "$ROBOT_USER:$ROBOT_PASS" \
        -X POST "https://robot-ws.your-server.de/vswitch" \
        -d "name=obmo-${var.pop_name}" \
        -d "vlan=4000"
    EOF
  }
}

# ===========================================
# Ansible Inventory
# ===========================================

resource "local_file" "inventory" {
  filename = "${path.module}/../../../ansible/inventory/hetzner-${var.pop_name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        hetzner_servers = {
          hosts = {}  # Populated after provisioning
          vars = {
            ansible_user       = "root"
            pop_name           = var.pop_name
            provider           = "hetzner"
            nic_type           = local.spec.nic_type
            nic_speed          = local.spec.speed
            controller_url     = var.controller_url
            activation_key     = var.activation_key
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
    price_month = local.spec.price
  }
}

output "inventory_path" {
  value = local_file.inventory.filename
}
