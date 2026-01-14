# OBMO Scaleway Module (TIER 2 - EU WITH GOOD PEERING)
# Elastic Metal bare metal servers

terraform {
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.28"
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
    zone           = string  # fr-par-1, fr-par-2, nl-ams-1, pl-waw-1
    region         = string
    environment    = string
    controller_url = string
    activation_key = string
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
  # Scaleway Elastic Metal (bare metal)
  # EM-A115X-SSD: AMD EPYC 7543, 256GB RAM, 2x25Gbps
  # EM-A410X-SSD: AMD EPYC 9454, 512GB RAM, 2x100Gbps
  server_type = var.high_performance ? "EM-A410X-SSD" : "EM-A115X-SSD"
  
  nic_info = {
    "EM-A410X-SSD" = { type = "mellanox_cx5", speed = 200 }
    "EM-A115X-SSD" = { type = "intel_xxv710", speed = 50 }
  }
  
  tags = ["opensase", "pop:${var.pop_config.name}", "env:${var.pop_config.environment}"]
}

# ===========================================
# SSH Key
# ===========================================

resource "scaleway_iam_ssh_key" "opensase" {
  name       = "opensase-${var.pop_config.name}"
  public_key = var.ssh_public_key
}

# ===========================================
# Private Network
# ===========================================

resource "scaleway_vpc_private_network" "pop_network" {
  name   = "opensase-${var.pop_config.name}-net"
  region = var.pop_config.region
  tags   = local.tags
}

# ===========================================
# Primary Elastic Metal Server
# ===========================================

resource "scaleway_baremetal_server" "pop_primary" {
  name  = "opensase-${var.pop_config.name}-01"
  zone  = var.pop_config.zone
  offer = local.server_type
  
  os = "ubuntu_jammy"
  
  ssh_key_ids = [scaleway_iam_ssh_key.opensase.id]
  
  tags = concat(local.tags, ["role:primary"])
  
  private_network {
    id = scaleway_vpc_private_network.pop_network.id
  }
  
  # Install via cloud-init
  install_config_afterward = true
}

# ===========================================
# Secondary Server for HA
# ===========================================

resource "scaleway_baremetal_server" "pop_secondary" {
  count = var.enable_ha ? 1 : 0
  
  name  = "opensase-${var.pop_config.name}-02"
  zone  = var.pop_config.zone
  offer = local.server_type
  
  os = "ubuntu_jammy"
  
  ssh_key_ids = [scaleway_iam_ssh_key.opensase.id]
  
  tags = concat(local.tags, ["role:secondary"])
  
  private_network {
    id = scaleway_vpc_private_network.pop_network.id
  }
}

# ===========================================
# Flexible IPs for Anycast
# ===========================================

resource "scaleway_flexible_ip" "primary" {
  server_id = scaleway_baremetal_server.pop_primary.id
  zone      = var.pop_config.zone
  reverse   = "opensase-${var.pop_config.name}-01.opensase.io"
}

resource "scaleway_flexible_ip" "secondary" {
  count = var.enable_ha ? 1 : 0
  
  server_id = scaleway_baremetal_server.pop_secondary[0].id
  zone      = var.pop_config.zone
  reverse   = "opensase-${var.pop_config.name}-02.opensase.io"
}

resource "scaleway_flexible_ip" "anycast" {
  zone    = var.pop_config.zone
  reverse = "anycast.${var.pop_config.name}.opensase.io"
}

# ===========================================
# Configure Servers
# ===========================================

resource "null_resource" "configure_primary" {
  depends_on = [scaleway_flexible_ip.primary]
  
  triggers = {
    server_id = scaleway_baremetal_server.pop_primary.id
  }
  
  connection {
    type        = "ssh"
    user        = "root"
    host        = scaleway_flexible_ip.primary.ip_address
    private_key = file("~/.ssh/opensase")
  }
  
  provisioner "remote-exec" {
    inline = [
      "#!/bin/bash",
      "set -e",
      
      "apt-get update && apt-get upgrade -y",
      
      "# Configure sysctl",
      "cat >> /etc/sysctl.conf << 'EOF'",
      "net.core.rmem_max = 536870912",
      "net.core.wmem_max = 536870912",
      "net.ipv4.ip_forward = 1",
      "vm.nr_hugepages = 8192",
      "EOF",
      "sysctl -p",
      
      "# Install VPP",
      "curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash",
      "apt-get install -y vpp vpp-plugin-core vpp-plugin-dpdk vpp-plugin-wireguard",
      
      "# Install FlexiEdge",
      "curl -sL https://deb.flexiwan.com/setup | bash",
      "apt-get install -y flexiwan-router",
      
      "# Configure FlexiEdge",
      "mkdir -p /etc/flexiwan",
      "cat > /etc/flexiwan/agent.conf << EOF",
      "{",
      "  \"deviceName\": \"opensase-${var.pop_config.name}-01\",",
      "  \"dataPlane\": \"vpp\",",
      "  \"managementUrl\": \"${var.pop_config.controller_url}\",",
      "  \"token\": \"${var.pop_config.activation_key}\"",
      "}",
      "EOF",
      
      "systemctl enable vpp flexiwan",
      "systemctl start vpp",
      "sleep 3",
      "systemctl start flexiwan"
    ]
  }
}

# ===========================================
# Ansible Inventory
# ===========================================

resource "local_file" "inventory" {
  filename = "${path.module}/../../../ansible/inventory/scaleway-${var.pop_config.name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        scaleway_servers = {
          hosts = merge(
            {
              "opensase-${var.pop_config.name}-01" = {
                ansible_host = scaleway_flexible_ip.primary.ip_address
                private_ip   = scaleway_baremetal_server.pop_primary.private_network[0].ip
                role         = "primary"
              }
            },
            var.enable_ha ? {
              "opensase-${var.pop_config.name}-02" = {
                ansible_host = scaleway_flexible_ip.secondary[0].ip_address
                private_ip   = scaleway_baremetal_server.pop_secondary[0].private_network[0].ip
                role         = "secondary"
              }
            } : {}
          )
          vars = {
            ansible_user   = "root"
            pop_name       = var.pop_config.name
            provider       = "scaleway"
            nic_type       = local.nic_info[local.server_type].type
            nic_speed      = local.nic_info[local.server_type].speed
            controller_url = var.pop_config.controller_url
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
    pop_name    = var.pop_config.name
    zone        = var.pop_config.zone
    server_type = local.server_type
    nic_type    = local.nic_info[local.server_type].type
    nic_speed   = local.nic_info[local.server_type].speed
    primary_ip  = scaleway_flexible_ip.primary.ip_address
    secondary_ip = var.enable_ha ? scaleway_flexible_ip.secondary[0].ip_address : null
    anycast_ip  = scaleway_flexible_ip.anycast.ip_address
  }
}

output "public_ips" {
  value = concat(
    [scaleway_flexible_ip.primary.ip_address],
    var.enable_ha ? [scaleway_flexible_ip.secondary[0].ip_address] : []
  )
}

output "private_ips" {
  value = concat(
    [scaleway_baremetal_server.pop_primary.private_network[0].ip],
    var.enable_ha ? [scaleway_baremetal_server.pop_secondary[0].private_network[0].ip] : []
  )
}

output "anycast_ip" {
  value = scaleway_flexible_ip.anycast.ip_address
}

output "server_ids" {
  value = concat(
    [scaleway_baremetal_server.pop_primary.id],
    var.enable_ha ? [scaleway_baremetal_server.pop_secondary[0].id] : []
  )
}
