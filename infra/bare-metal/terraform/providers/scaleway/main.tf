# OpenSASE Bare Metal Orchestrator - Scaleway Module
# Elastic Metal Dedicated Servers

terraform {
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.34"
    }
  }
}

# ===========================================
# Variables
# ===========================================

variable "pop_name" {
  type = string
}

variable "zone" {
  description = "Scaleway zone (fr-par-1, nl-ams-1)"
  type        = string
  default     = "fr-par-2"
}

variable "offer" {
  description = "Elastic Metal offer (EM-L210E-NVME, EM-A315X-SSD)"
  type        = string
  default     = "EM-L210E-NVME"
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

variable "environment" {
  type    = string
  default = "production"
}

# ===========================================
# Locals
# ===========================================

locals {
  offer_specs = {
    "EM-L210E-NVME" = {
      cores    = 32
      ram_gb   = 128
      nic_type = "intel_x710"
      speed    = 20
    }
    "EM-A315X-SSD" = {
      cores    = 64
      ram_gb   = 256
      nic_type = "intel_xxv710"
      speed    = 45
    }
    "EM-A410X-SSD" = {
      cores    = 96
      ram_gb   = 384
      nic_type = "intel_xxv710"
      speed    = 50
    }
  }
  
  spec = local.offer_specs[var.offer]
  
  tags = [
    "opensase",
    "obmo",
    "pop-${var.pop_name}",
    "env-${var.environment}"
  ]
}

# ===========================================
# SSH Key
# ===========================================

resource "scaleway_iam_ssh_key" "obmo" {
  name       = "obmo-${var.pop_name}"
  public_key = var.ssh_public_key
}

# ===========================================
# Private Network
# ===========================================

resource "scaleway_vpc_private_network" "obmo" {
  name = "obmo-${var.pop_name}-private"
  tags = local.tags
}

# ===========================================
# Elastic Metal Servers
# ===========================================

resource "scaleway_baremetal_server" "server" {
  count = var.instance_count
  
  name  = "obmo-${var.pop_name}-${format("%02d", count.index + 1)}"
  zone  = var.zone
  offer = var.offer
  
  os = "ubuntu_jammy"
  
  ssh_key_ids = [scaleway_iam_ssh_key.obmo.id]
  
  private_network {
    id = scaleway_vpc_private_network.obmo.id
  }
  
  tags = local.tags
  
  # Install script via cloud-init
  install_config_afterward = true
}

# ===========================================
# Flexible IPs
# ===========================================

resource "scaleway_flexible_ip" "server" {
  count = var.instance_count
  
  server_id = scaleway_baremetal_server.server[count.index].id
  zone      = var.zone
  
  tags = local.tags
}

# ===========================================
# Configure Servers
# ===========================================

resource "null_resource" "configure" {
  count = var.instance_count
  
  depends_on = [
    scaleway_baremetal_server.server,
    scaleway_flexible_ip.server
  ]
  
  triggers = {
    server_id = scaleway_baremetal_server.server[count.index].id
  }
  
  connection {
    type        = "ssh"
    user        = "root"
    host        = scaleway_flexible_ip.server[count.index].ip_address
    private_key = file("~/.ssh/opensase")
  }
  
  provisioner "remote-exec" {
    inline = [
      "#!/bin/bash",
      "set -e",
      
      "# Update system",
      "apt-get update && apt-get upgrade -y",
      
      "# Configure sysctl for 100G",
      "cat >> /etc/sysctl.conf << 'EOF'",
      "net.core.rmem_max = 536870912",
      "net.core.wmem_max = 536870912",
      "net.ipv4.ip_forward = 1",
      "vm.nr_hugepages = 4096",
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
      "  \"deviceName\": \"obmo-${var.pop_name}-${count.index + 1}\",",
      "  \"dataPlane\": \"vpp\",",
      "  \"managementUrl\": \"${var.controller_url}\",",
      "  \"token\": \"${var.activation_key}\"",
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
  filename = "${path.module}/../../../ansible/inventory/scaleway-${var.pop_name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        scaleway_servers = {
          hosts = { for i, s in scaleway_baremetal_server.server :
            "obmo-${var.pop_name}-${format("%02d", i + 1)}" => {
              ansible_host = scaleway_flexible_ip.server[i].ip_address
              private_ip   = s.private_network[0].ip
            }
          }
          vars = {
            ansible_user   = "root"
            pop_name       = var.pop_name
            provider       = "scaleway"
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
    name       = var.pop_name
    zone       = var.zone
    offer      = var.offer
    nic_type   = local.spec.nic_type
    speed_gbps = local.spec.speed
  }
}

output "public_ips" {
  value = [for ip in scaleway_flexible_ip.server : ip.ip_address]
}

output "private_ips" {
  value = [for s in scaleway_baremetal_server.server : s.private_network[0].ip]
}

output "server_ids" {
  value = [for s in scaleway_baremetal_server.server : s.id]
}

output "ssh_commands" {
  value = [for ip in scaleway_flexible_ip.server : "ssh root@${ip.ip_address}"]
}
