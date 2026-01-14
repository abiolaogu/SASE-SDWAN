# OBMO Hetzner Module (TIER 2 - EXTREMELY COST-EFFECTIVE)
# Robot API for dedicated servers + hcloud for networking

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

variable "pop_config" {
  description = "PoP configuration object"
  type = object({
    name           = string
    location       = string  # fsn1, nbg1, hel1
    environment    = string
    controller_url = string
    activation_key = string
    network_id     = number
  })
}

variable "high_performance" {
  description = "Use high-performance servers"
  type        = bool
  default     = true
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

variable "management_ips" {
  description = "IPs allowed for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "bgp_peer_ips" {
  description = "BGP peer IPs"
  type        = list(string)
  default     = []
}

# ===========================================
# Locals
# ===========================================

locals {
  # Hetzner dedicated server recommendations for 100 Gbps:
  # AX161: AMD EPYC 9454P, 128GB DDR5, 2x10Gbps
  # SX134: AMD EPYC 9354P, 256GB DDR5, 2x25Gbps
  server_product = var.high_performance ? "SX134" : "AX161"
  
  nic_info = {
    "SX134" = { type = "intel_xxv710", speed = 50 }
    "AX161" = { type = "intel_x710", speed = 20 }
  }
}

# ===========================================
# SSH Key
# ===========================================

resource "hcloud_ssh_key" "opensase" {
  name       = "opensase-${var.pop_config.name}"
  public_key = var.ssh_public_key
}

# ===========================================
# Private Network
# ===========================================

resource "hcloud_network" "pop_network" {
  name     = "opensase-${var.pop_config.name}-net"
  ip_range = "10.${var.pop_config.network_id}.0.0/16"
}

resource "hcloud_network_subnet" "pop_subnet" {
  network_id   = hcloud_network.pop_network.id
  type         = "server"
  network_zone = var.pop_config.location == "hel1" ? "eu-central" : "eu-central"
  ip_range     = "10.${var.pop_config.network_id}.1.0/24"
}

# ===========================================
# Firewall
# ===========================================

resource "hcloud_firewall" "pop_firewall" {
  name = "opensase-${var.pop_config.name}-fw"
  
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.management_ips
  }
  
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "51820"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "179"
    source_ips = var.bgp_peer_ips
  }
  
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "8080"
    source_ips = var.management_ips
  }
}

# ===========================================
# Robot API Script for Server Ordering
# ===========================================

resource "local_file" "hetzner_order_script" {
  filename = "${path.module}/scripts/order-${var.pop_config.name}.sh"
  file_permission = "0755"
  
  content = <<-EOF
#!/bin/bash
# Hetzner Robot API - Order Dedicated Server
# PoP: ${var.pop_config.name}

set -euo pipefail

ROBOT_USER="${var.robot_user}"
ROBOT_PASS="${var.robot_password}"
PRODUCT="${local.server_product}"
DATACENTER="${var.pop_config.location}"

echo "=== Ordering Hetzner Dedicated Server ==="
echo "Product: $PRODUCT"
echo "Datacenter: $DATACENTER"

# Search for available server
AVAILABLE=$(curl -su "$ROBOT_USER:$ROBOT_PASS" \
  "https://robot-ws.your-server.de/order/server/product" | \
  jq -r '.[] | select(.name == "'$PRODUCT'") | .id' | head -1)

if [ -z "$AVAILABLE" ]; then
  echo "ERROR: No $PRODUCT servers available"
  exit 1
fi

echo "Found available server: $AVAILABLE"

# Order the server
curl -su "$ROBOT_USER:$ROBOT_PASS" \
  -X POST "https://robot-ws.your-server.de/order/server/transaction" \
  -d "product_id=$AVAILABLE" \
  -d "location=${local.datacenter_mapping[var.pop_config.location]}" \
  -d "authorized_key=${var.ssh_public_key}" \
  -d "comment=OpenSASE ${var.pop_config.name}"

echo "=== Server Order Submitted ==="
echo "Check Hetzner Robot dashboard for status"
EOF
}

locals {
  datacenter_mapping = {
    "fsn1" = "FSN1-DC14"
    "nbg1" = "NBG1-DC3"
    "hel1" = "HEL1-DC2"
  }
}

# ===========================================
# Server Configuration Script
# ===========================================

resource "local_file" "configure_script" {
  filename = "${path.module}/scripts/configure-${var.pop_config.name}.sh"
  file_permission = "0755"
  
  content = templatefile("${path.module}/templates/configure.sh.tpl", {
    pop_name       = var.pop_config.name
    controller_url = var.pop_config.controller_url
    activation_key = var.pop_config.activation_key
    nic_type       = local.nic_info[local.server_product].type
    nic_speed      = local.nic_info[local.server_product].speed
    network_id     = hcloud_network.pop_network.id
  })
}

# ===========================================
# Ansible Inventory
# ===========================================

resource "local_file" "inventory" {
  filename = "${path.module}/../../../ansible/inventory/hetzner-${var.pop_config.name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        hetzner_servers = {
          hosts = {}  # Populated after Robot provisioning
          vars = {
            ansible_user       = "root"
            pop_name           = var.pop_config.name
            provider           = "hetzner"
            nic_type           = local.nic_info[local.server_product].type
            nic_speed          = local.nic_info[local.server_product].speed
            controller_url     = var.pop_config.controller_url
            activation_key     = var.pop_config.activation_key
            private_network_id = hcloud_network.pop_network.id
          }
        }
      }
    }
  })
}

# ===========================================
# vSwitch for Private Networking
# ===========================================

resource "null_resource" "vswitch" {
  triggers = {
    pop_name = var.pop_config.name
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      curl -su "${var.robot_user}:${var.robot_password}" \
        -X POST "https://robot-ws.your-server.de/vswitch" \
        -d "name=opensase-${var.pop_config.name}" \
        -d "vlan=40${var.pop_config.network_id}"
    EOF
  }
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  value = {
    pop_name       = var.pop_config.name
    location       = var.pop_config.location
    server_product = local.server_product
    nic_type       = local.nic_info[local.server_product].type
    nic_speed      = local.nic_info[local.server_product].speed
    network_id     = hcloud_network.pop_network.id
  }
}

output "network_id" {
  value = hcloud_network.pop_network.id
}

output "order_script" {
  value = local_file.hetzner_order_script.filename
}

output "configure_script" {
  value = local_file.configure_script.filename
}

output "ssh_key_id" {
  value = hcloud_ssh_key.opensase.id
}

output "firewall_id" {
  value = hcloud_firewall.pop_firewall.id
}
