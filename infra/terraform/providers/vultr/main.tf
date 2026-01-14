# Vultr Provider Configuration
# Cloud and bare metal servers globally

terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.17"
    }
  }
}

provider "vultr" {
  api_key     = var.vultr_api_key
  rate_limit  = 700
  retry_limit = 3
}

# ===========================================
# Variables
# ===========================================

variable "vultr_api_key" {
  description = "Vultr API key"
  type        = string
  sensitive   = true
}

variable "pop_name" {
  type = string
}

variable "region" {
  description = "Vultr region ID"
  type        = string
}

variable "plan" {
  description = "Server plan"
  type        = string
  default     = "vhf-8c-32gb"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "ssh_public_key" {
  type = string
}

variable "user_data" {
  type = string
}

variable "tags" {
  type = map(string)
}

# ===========================================
# Region Mapping
# ===========================================

locals {
  region_map = {
    "nyc" = "ewr"  # New Jersey
    "ldn" = "lhr"  # London
    "fra" = "fra"  # Frankfurt
    "ams" = "ams"  # Amsterdam
    "tok" = "nrt"  # Tokyo
    "syd" = "syd"  # Sydney
    "sin" = "sgp"  # Singapore
    "sjc" = "sjc"  # San Jose
    "lax" = "lax"  # Los Angeles
    "chi" = "ord"  # Chicago
    "mia" = "mia"  # Miami
    "sea" = "sea"  # Seattle
  }
  
  actual_region = lookup(local.region_map, var.region, var.region)
}

# ===========================================
# SSH Key
# ===========================================

resource "vultr_ssh_key" "pop" {
  name    = "opensase-${var.pop_name}"
  ssh_key = var.ssh_public_key
}

# ===========================================
# VPC for private networking
# ===========================================

resource "vultr_vpc" "pop" {
  region         = local.actual_region
  description    = "OpenSASE ${var.pop_name} VPC"
  v4_subnet      = "10.100.0.0"
  v4_subnet_mask = 24
}

# ===========================================
# Firewall Group
# ===========================================

resource "vultr_firewall_group" "pop" {
  description = "OpenSASE ${var.pop_name} firewall"
}

resource "vultr_firewall_rule" "ssh" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "22"
}

resource "vultr_firewall_rule" "https" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "443"
}

resource "vultr_firewall_rule" "wireguard" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "udp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "51820"
}

resource "vultr_firewall_rule" "flexiwan" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "4433"
}

# ===========================================
# Instances
# ===========================================

resource "vultr_instance" "pop" {
  count = var.instance_count
  
  label       = "opensase-${var.pop_name}-${count.index + 1}"
  region      = local.actual_region
  plan        = var.plan
  os_id       = 1743  # Ubuntu 22.04 LTS
  
  ssh_key_ids       = [vultr_ssh_key.pop.id]
  firewall_group_id = vultr_firewall_group.pop.id
  vpc_ids           = [vultr_vpc.pop.id]
  
  user_data = base64encode(var.user_data)
  
  enable_ipv6       = true
  backups           = "disabled"
  ddos_protection   = true
  activation_email  = false
  
  hostname = "opensase-${var.pop_name}-${count.index + 1}"
  
  tags = [for k, v in var.tags : "${k}=${v}"]
}

# ===========================================
# Load Balancer (optional)
# ===========================================

resource "vultr_load_balancer" "pop" {
  count = var.instance_count > 1 ? 1 : 0
  
  region              = local.actual_region
  label               = "opensase-${var.pop_name}-lb"
  balancing_algorithm = "roundrobin"
  
  forwarding_rules {
    frontend_protocol = "https"
    frontend_port     = 443
    backend_protocol  = "https"
    backend_port      = 443
  }
  
  forwarding_rules {
    frontend_protocol = "tcp"
    frontend_port     = 51820
    backend_protocol  = "tcp"
    backend_port      = 51820
  }
  
  health_check {
    protocol            = "https"
    port                = 443
    path                = "/health"
    check_interval      = 15
    response_timeout    = 5
    unhealthy_threshold = 3
    healthy_threshold   = 2
  }
  
  attached_instances = [for i in vultr_instance.pop : i.id]
}

# ===========================================
# Outputs
# ===========================================

output "public_ips" {
  value = [for i in vultr_instance.pop : i.main_ip]
}

output "private_ips" {
  value = [for i in vultr_instance.pop : i.internal_ip]
}

output "instance_ids" {
  value = [for i in vultr_instance.pop : i.id]
}

output "vpc_id" {
  value = vultr_vpc.pop.id
}

output "load_balancer_ip" {
  value = var.instance_count > 1 ? vultr_load_balancer.pop[0].ipv4 : null
}
