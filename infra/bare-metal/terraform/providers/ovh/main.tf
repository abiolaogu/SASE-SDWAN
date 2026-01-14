# OBMO OVH Cloud Module (TIER 2 - COST-EFFECTIVE EU/NA)
# Dedicated Servers with vRack support

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

variable "pop_config" {
  description = "PoP configuration object"
  type = object({
    name           = string
    datacenter     = string  # rbx, gra, sbg, bhs, waw, etc.
    environment    = string
    controller_url = string
    activation_key = string
  })
}

variable "ovh_service_name" {
  description = "OVH dedicated server service name"
  type        = string
}

variable "vrack_service_name" {
  description = "OVH vRack service name for private networking"
  type        = string
  default     = ""
}

variable "high_performance" {
  description = "Use high-performance servers"
  type        = bool
  default     = true
}

variable "ssh_public_keys" {
  description = "SSH public keys"
  type        = list(string)
  default     = []
}

variable "ovh_subsidiary" {
  description = "OVH subsidiary (EU, CA, US)"
  type        = string
  default     = "EU"
}

# ===========================================
# Locals
# ===========================================

locals {
  # OVH Dedicated Server Plans for high bandwidth
  # SCALE-7: AMD EPYC 7763, 128GB RAM, 2x25Gbps NIC
  # HGR-HCI-2: Intel Xeon, 384GB RAM, 2x25Gbps + 1x100Gbps NIC
  # HGR-SDS-1: AMD EPYC, 512GB RAM, 2x100Gbps Mellanox
  server_plan = var.high_performance ? "24ska01" : "22sk010"
  
  datacenter_regions = {
    rbx = "eu-west-rbx"
    gra = "eu-west-gra"
    sbg = "eu-west-sbg"
    bhs = "ca-east-bhs"
    waw = "eu-central-waw"
    sgp = "ap-southeast-sgp"
    syd = "ap-southeast-syd"
  }
}

# ===========================================
# Data Source: Existing Server
# ===========================================

data "ovh_dedicated_server" "pop_server" {
  service_name = var.ovh_service_name
}

# ===========================================
# Server Installation Task
# ===========================================

resource "ovh_dedicated_server_install_task" "pop_server" {
  service_name = data.ovh_dedicated_server.pop_server.service_name
  
  details {
    custom_hostname = "opensase-${var.pop_config.name}-01"
  }
  
  template_name = "ubuntu2204-server_64"
  
  user_metadata {
    key   = "ssh_authorized_keys"
    value = join("\n", var.ssh_public_keys)
  }
}

# ===========================================
# vRack Configuration
# ===========================================

resource "ovh_vrack_dedicated_server" "pop_vrack" {
  count = var.vrack_service_name != "" ? 1 : 0
  
  service_name = var.vrack_service_name
  server_id    = data.ovh_dedicated_server.pop_server.service_name
}

# ===========================================
# IP Failover for Anycast
# ===========================================

resource "ovh_ip_service" "anycast" {
  ovh_subsidiary = var.ovh_subsidiary
  description    = "OpenSASE Anycast - ${var.pop_config.name}"
}

# ===========================================
# Route IP to Server
# ===========================================

resource "ovh_ip_move" "anycast_to_server" {
  ip           = ovh_ip_service.anycast.ip
  routed_to_id = data.ovh_dedicated_server.pop_server.service_name
}

# ===========================================
# Configure Server via SSH
# ===========================================

resource "null_resource" "configure_server" {
  depends_on = [ovh_dedicated_server_install_task.pop_server]
  
  triggers = {
    server_ip = data.ovh_dedicated_server.pop_server.ip
  }
  
  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      user        = "root"
      host        = data.ovh_dedicated_server.pop_server.ip
      private_key = file("~/.ssh/opensase")
      timeout     = "10m"
    }
    
    inline = [
      "#!/bin/bash",
      "set -e",
      
      "# System updates",
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
  filename = "${path.module}/../../../ansible/inventory/ovh-${var.pop_config.name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        ovh_servers = {
          hosts = {
            "opensase-${var.pop_config.name}-01" = {
              ansible_host = data.ovh_dedicated_server.pop_server.ip
              anycast_ip   = ovh_ip_service.anycast.ip
            }
          }
          vars = {
            ansible_user   = "root"
            pop_name       = var.pop_config.name
            provider       = "ovh"
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
    pop_name   = var.pop_config.name
    datacenter = var.pop_config.datacenter
    primary_ip = data.ovh_dedicated_server.pop_server.ip
    anycast_ip = ovh_ip_service.anycast.ip
    vrack      = var.vrack_service_name != "" ? var.vrack_service_name : null
  }
}

output "public_ips" {
  value = [data.ovh_dedicated_server.pop_server.ip]
}

output "anycast_ip" {
  value = ovh_ip_service.anycast.ip
}

output "server_info" {
  value = {
    service_name = data.ovh_dedicated_server.pop_server.service_name
    ip           = data.ovh_dedicated_server.pop_server.ip
    datacenter   = var.pop_config.datacenter
  }
}
