# OBMO Cloudflare DNS Module

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.20"
    }
  }
}

variable "pop_name" {
  type = string
}

variable "domain" {
  description = "Base domain"
  type        = string
  default     = "opensase.io"
}

variable "zone_id" {
  description = "Cloudflare zone ID"
  type        = string
}

variable "server_ips" {
  description = "Public IPs of PoP servers"
  type        = list(string)
}

variable "anycast_ips" {
  description = "Anycast IPs for load balancing"
  type        = list(string)
  default     = []
}

variable "enable_proxy" {
  description = "Enable Cloudflare proxy"
  type        = bool
  default     = false
}

variable "health_check_path" {
  type    = string
  default = "/health"
}

# ===========================================
# DNS Records
# ===========================================

resource "cloudflare_record" "pop" {
  count = length(var.server_ips)
  
  zone_id = var.zone_id
  name    = var.pop_name
  value   = var.server_ips[count.index]
  type    = "A"
  ttl     = 60
  proxied = var.enable_proxy
  
  comment = "OBMO ${var.pop_name} server ${count.index + 1}"
}

resource "cloudflare_record" "pop_api" {
  zone_id = var.zone_id
  name    = "api.${var.pop_name}"
  value   = length(var.anycast_ips) > 0 ? var.anycast_ips[0] : var.server_ips[0]
  type    = "A"
  ttl     = 60
  proxied = var.enable_proxy
  
  comment = "OBMO ${var.pop_name} API endpoint"
}

resource "cloudflare_record" "pop_mgmt" {
  count = length(var.server_ips)
  
  zone_id = var.zone_id
  name    = "${var.pop_name}-${format("%02d", count.index + 1)}"
  value   = var.server_ips[count.index]
  type    = "A"
  ttl     = 60
  proxied = false
  
  comment = "OBMO ${var.pop_name} server ${count.index + 1} direct"
}

# ===========================================
# Health Checks
# ===========================================

resource "cloudflare_healthcheck" "pop" {
  count = length(var.server_ips)
  
  zone_id     = var.zone_id
  name        = "obmo-${var.pop_name}-${count.index + 1}"
  description = "Health check for ${var.pop_name} server ${count.index + 1}"
  address     = var.server_ips[count.index]
  
  type = "HTTPS"
  port = 443
  path = var.health_check_path
  
  check_regions = ["WNAM", "ENAM", "WEU", "EEU", "SEAS", "NEAS"]
  
  interval         = 60
  timeout          = 5
  retries          = 2
  consecutive_fails = 3
  consecutive_successes = 2

  header {
    header = "Host"
    values = ["${var.pop_name}.${var.domain}"]
  }
}

# ===========================================
# Load Balancer (if multiple IPs)
# ===========================================

resource "cloudflare_load_balancer_pool" "pop" {
  count = length(var.anycast_ips) > 0 || length(var.server_ips) > 1 ? 1 : 0
  
  account_id = var.zone_id
  name       = "obmo-${var.pop_name}-pool"
  
  dynamic "origins" {
    for_each = length(var.anycast_ips) > 0 ? var.anycast_ips : var.server_ips
    content {
      name    = "origin-${origins.key + 1}"
      address = origins.value
      enabled = true
    }
  }
  
  monitor = cloudflare_load_balancer_monitor.pop[0].id
}

resource "cloudflare_load_balancer_monitor" "pop" {
  count = length(var.anycast_ips) > 0 || length(var.server_ips) > 1 ? 1 : 0
  
  account_id     = var.zone_id
  type           = "https"
  expected_codes = "2xx"
  path           = var.health_check_path
  interval       = 60
  timeout        = 5
  retries        = 2
}

# ===========================================
# Outputs
# ===========================================

output "dns_records" {
  value = {
    pop_hosts = [for r in cloudflare_record.pop : r.hostname]
    api       = cloudflare_record.pop_api.hostname
    mgmt      = [for r in cloudflare_record.pop_mgmt : r.hostname]
  }
}

output "health_check_ids" {
  value = [for h in cloudflare_healthcheck.pop : h.id]
}
