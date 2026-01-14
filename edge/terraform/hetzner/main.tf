# OpenSASE Edge - Hetzner Dedicated Server
# Terraform configuration for deploying edge nodes on Hetzner

terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.42"
    }
  }
}

provider "hcloud" {
  token = var.hetzner_token
}

variable "hetzner_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "ssh_keys" {
  description = "SSH key names for access"
  type        = list(string)
  default     = []
}

variable "location" {
  description = "Hetzner datacenter location"
  type        = string
  default     = "fsn1"  # Falkenstein
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "cx31"  # 2 vCPU, 8GB RAM (cloud), or use dedicated via Robot
}

variable "edge_count" {
  description = "Number of edge servers"
  type        = number
  default     = 1
}

# Edge Server
resource "hcloud_server" "edge" {
  count       = var.edge_count
  name        = "opensase-edge-${var.location}-${count.index}"
  server_type = var.server_type
  location    = var.location
  image       = "ubuntu-22.04"
  
  ssh_keys = var.ssh_keys
  
  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y docker.io wireguard-tools
    systemctl enable docker
    systemctl start docker
    
    # Pull OpenSASE Edge image
    docker pull opensase/edge:latest
    
    # Configure WireGuard
    mkdir -p /etc/wireguard
    wg genkey > /etc/wireguard/private.key
    wg pubkey < /etc/wireguard/private.key > /etc/wireguard/public.key
  EOF
  
  labels = {
    project = "opensase"
    role    = "edge"
  }
}

# Private Network
resource "hcloud_network" "edge_network" {
  name     = "opensase-edge-network"
  ip_range = "10.0.0.0/16"
}

resource "hcloud_network_subnet" "edge_subnet" {
  network_id   = hcloud_network.edge_network.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "10.0.1.0/24"
}

resource "hcloud_server_network" "edge_network_attach" {
  count      = var.edge_count
  server_id  = hcloud_server.edge[count.index].id
  network_id = hcloud_network.edge_network.id
}

# Firewall
resource "hcloud_firewall" "edge_fw" {
  name = "opensase-edge-firewall"
  
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
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
    protocol   = "udp"
    port       = "51820"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_firewall_attachment" "edge_fw_attach" {
  count       = var.edge_count
  firewall_id = hcloud_firewall.edge_fw.id
  server_ids  = [hcloud_server.edge[count.index].id]
}

# Outputs
output "edge_public_ips" {
  description = "Public IP addresses of edge servers"
  value       = hcloud_server.edge[*].ipv4_address
}

output "edge_private_ips" {
  description = "Private network IPs"
  value       = [for s in hcloud_server_network.edge_network_attach : s.ip]
}
