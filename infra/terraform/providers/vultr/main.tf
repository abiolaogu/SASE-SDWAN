# Vultr PoP Module - Cloud and Bare Metal
# Cost-effective high-performance edge nodes

terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.17"
    }
  }
}

# ===========================================
# Variables
# ===========================================

variable "pop_name" {
  description = "Name of the PoP"
  type        = string
}

variable "region" {
  description = "Vultr region ID (e.g., ewr, lhr, sgp)"
  type        = string
}

variable "deployment_type" {
  description = "Deployment type: cloud or bare_metal"
  type        = string
  default     = "cloud"
  
  validation {
    condition     = contains(["cloud", "bare_metal"], var.deployment_type)
    error_message = "Deployment type must be 'cloud' or 'bare_metal'."
  }
}

variable "cloud_plan" {
  description = "Cloud instance plan"
  type        = string
  default     = "vhp-8c-32gb-amd"
}

variable "bare_metal_plan" {
  description = "Bare metal plan"
  type        = string
  default     = "vbm-24c-256gb-amd"
}

variable "instance_count" {
  description = "Number of instances"
  type        = number
  default     = 2
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

variable "enable_ddos" {
  description = "Enable DDoS protection"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable backups"
  type        = bool
  default     = false
}

variable "reserved_ip_count" {
  description = "Number of reserved IPs"
  type        = number
  default     = 2
}

variable "tags" {
  type    = map(string)
  default = {}
}

# ===========================================
# Locals
# ===========================================

locals {
  common_tags = concat(
    ["opensase", "pop-${var.pop_name}", "env-${var.environment}"],
    [for k, v in var.tags : "${k}=${v}"]
  )
  
  region_map = {
    "nyc" = "ewr"
    "ldn" = "lhr"
    "fra" = "fra"
    "ams" = "ams"
    "tok" = "nrt"
    "syd" = "syd"
    "sin" = "sgp"
    "sjc" = "sjc"
    "lax" = "lax"
    "chi" = "ord"
    "mia" = "mia"
    "sea" = "sea"
    "par" = "cdg"
    "mad" = "mad"
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
# VPC for Private Networking
# ===========================================

resource "vultr_vpc" "pop" {
  region         = local.actual_region
  description    = "OpenSASE ${var.pop_name} VPC"
  v4_subnet      = "10.100.0.0"
  v4_subnet_mask = 24
}

resource "vultr_vpc2" "pop_v2" {
  region         = local.actual_region
  description    = "OpenSASE ${var.pop_name} VPC v2"
  ip_block       = "10.200.0.0"
  prefix_length  = 24
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
  notes             = "SSH"
}

resource "vultr_firewall_rule" "https" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "443"
  notes             = "HTTPS"
}

resource "vultr_firewall_rule" "http" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "80"
  notes             = "HTTP"
}

resource "vultr_firewall_rule" "wireguard" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "udp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "51820"
  notes             = "WireGuard"
}

resource "vultr_firewall_rule" "flexiwan" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "4433"
  notes             = "FlexiWAN"
}

resource "vultr_firewall_rule" "health" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "10.0.0.0"
  subnet_size       = 8
  port              = "8080"
  notes             = "Health API"
}

resource "vultr_firewall_rule" "prometheus" {
  firewall_group_id = vultr_firewall_group.pop.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "10.0.0.0"
  subnet_size       = 8
  port              = "9100"
  notes             = "Node Exporter"
}

# ===========================================
# Reserved IPs
# ===========================================

resource "vultr_reserved_ip" "pop" {
  count = var.reserved_ip_count
  
  region   = local.actual_region
  ip_type  = "v4"
  label    = "opensase-${var.pop_name}-ip-${count.index + 1}"
}

# ===========================================
# Cloud Instances
# ===========================================

resource "vultr_instance" "pop" {
  count = var.deployment_type == "cloud" ? var.instance_count : 0
  
  label     = "opensase-${var.pop_name}-${format("%02d", count.index + 1)}"
  region    = local.actual_region
  plan      = var.cloud_plan
  os_id     = 1743  # Ubuntu 22.04 LTS
  
  ssh_key_ids       = [vultr_ssh_key.pop.id]
  firewall_group_id = vultr_firewall_group.pop.id
  vpc_ids           = [vultr_vpc.pop.id]
  vpc2_ids          = [vultr_vpc2.pop_v2.id]
  
  user_data = base64encode(templatefile("${path.module}/templates/userdata.sh.tpl", {
    pop_name       = var.pop_name
    server_index   = count.index + 1
    controller_url = var.controller_url
    activation_key = var.activation_key
    is_primary     = count.index == 0
  }))
  
  enable_ipv6      = true
  backups          = var.enable_backup ? "enabled" : "disabled"
  ddos_protection  = var.enable_ddos
  activation_email = false
  hostname         = "opensase-${var.pop_name}-${format("%02d", count.index + 1)}"
  
  tags = local.common_tags
}

# ===========================================
# Bare Metal Servers
# ===========================================

resource "vultr_bare_metal_server" "pop" {
  count = var.deployment_type == "bare_metal" ? var.instance_count : 0
  
  label     = "opensase-${var.pop_name}-bm-${format("%02d", count.index + 1)}"
  region    = local.actual_region
  plan      = var.bare_metal_plan
  os_id     = 1743  # Ubuntu 22.04
  
  ssh_key_ids = [vultr_ssh_key.pop.id]
  
  user_data = base64encode(templatefile("${path.module}/templates/userdata-baremetal.sh.tpl", {
    pop_name       = var.pop_name
    server_index   = count.index + 1
    controller_url = var.controller_url
    activation_key = var.activation_key
    is_primary     = count.index == 0
  }))
  
  enable_ipv6      = true
  activation_email = false
  hostname         = "opensase-${var.pop_name}-bm-${format("%02d", count.index + 1)}"
  
  tags = local.common_tags
}

# ===========================================
# Assign Reserved IPs
# ===========================================

resource "vultr_instance_ipv4" "reserved" {
  count = var.deployment_type == "cloud" && var.instance_count > 0 ? min(var.reserved_ip_count, var.instance_count) : 0
  
  instance_id = vultr_instance.pop[count.index].id
  reboot      = false
}

# ===========================================
# Load Balancer
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
    frontend_protocol = "http"
    frontend_port     = 80
    backend_protocol  = "http"
    backend_port      = 80
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
  
  ssl {
    private_key = file("${path.module}/certs/server.key")
    certificate = file("${path.module}/certs/server.crt")
    chain       = file("${path.module}/certs/ca.crt")
  }
  
  attached_instances = var.deployment_type == "cloud" ? [for i in vultr_instance.pop : i.id] : []
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  value = {
    name            = var.pop_name
    region          = local.actual_region
    deployment_type = var.deployment_type
  }
}

output "public_ips" {
  value = var.deployment_type == "cloud" ? [
    for i in vultr_instance.pop : i.main_ip
  ] : [
    for s in vultr_bare_metal_server.pop : s.main_ip
  ]
}

output "private_ips" {
  value = var.deployment_type == "cloud" ? [
    for i in vultr_instance.pop : i.internal_ip
  ] : []
}

output "ipv6_addresses" {
  value = var.deployment_type == "cloud" ? [
    for i in vultr_instance.pop : i.v6_main_ip
  ] : [
    for s in vultr_bare_metal_server.pop : s.v6_main_ip
  ]
}

output "reserved_ips" {
  value = [for ip in vultr_reserved_ip.pop : ip.subnet]
}

output "load_balancer_ip" {
  value = var.instance_count > 1 ? vultr_load_balancer.pop[0].ipv4 : null
}

output "vpc_info" {
  value = {
    v1_id     = vultr_vpc.pop.id
    v2_id     = vultr_vpc2.pop_v2.id
    v1_subnet = "${vultr_vpc.pop.v4_subnet}/${vultr_vpc.pop.v4_subnet_mask}"
    v2_subnet = "${vultr_vpc2.pop_v2.ip_block}/${vultr_vpc2.pop_v2.prefix_length}"
  }
}

output "ssh_commands" {
  value = var.deployment_type == "cloud" ? [
    for i in vultr_instance.pop : "ssh root@${i.main_ip}"
  ] : [
    for s in vultr_bare_metal_server.pop : "ssh root@${s.main_ip}"
  ]
}
