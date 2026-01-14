# OpenSASE DNS Module
# Cloudflare DNS with GeoDNS and health checks

variable "domain" {
  type = string
}

variable "pop_name" {
  type = string
}

variable "instance_ips" {
  type = list(string)
}

variable "enable_geo_dns" {
  type    = bool
  default = true
}

variable "health_check" {
  type = object({
    path     = string
    port     = number
    protocol = string
  })
}

# ===========================================
# Data Sources
# ===========================================

data "cloudflare_zone" "main" {
  name = var.domain
}

# ===========================================
# Health Check
# ===========================================

resource "cloudflare_healthcheck" "pop" {
  zone_id = data.cloudflare_zone.main.id
  
  name = "opensase-${var.pop_name}-health"
  
  address = var.instance_ips[0]
  
  type = var.health_check.protocol
  port = var.health_check.port
  path = var.health_check.path
  
  check_regions = ["WNAM", "ENAM", "WEU", "EEU", "SEAS", "NEAS"]
  
  interval         = 60
  retries          = 2
  timeout          = 5
  consecutive_up   = 2
  consecutive_down = 2
  
  header {
    header = "Host"
    values = ["${var.pop_name}.${var.domain}"]
  }
}

# ===========================================
# DNS Records - Load Balanced
# ===========================================

resource "cloudflare_record" "pop_lb" {
  count = length(var.instance_ips)
  
  zone_id = data.cloudflare_zone.main.id
  name    = var.pop_name
  type    = "A"
  value   = var.instance_ips[count.index]
  ttl     = 60
  proxied = false
  
  # Comment for identification
  comment = "OpenSASE ${var.pop_name} instance ${count.index + 1}"
}

# Wildcard for subdomains
resource "cloudflare_record" "pop_wildcard" {
  count = length(var.instance_ips)
  
  zone_id = data.cloudflare_zone.main.id
  name    = "*.${var.pop_name}"
  type    = "A"
  value   = var.instance_ips[count.index]
  ttl     = 60
  proxied = false
}

# API endpoint
resource "cloudflare_record" "pop_api" {
  count = length(var.instance_ips)
  
  zone_id = data.cloudflare_zone.main.id
  name    = "api.${var.pop_name}"
  type    = "A"
  value   = var.instance_ips[count.index]
  ttl     = 60
  proxied = true
}

# ===========================================
# Load Balancer (Cloudflare Load Balancing)
# ===========================================

resource "cloudflare_load_balancer_pool" "pop" {
  count = var.enable_geo_dns ? 1 : 0
  
  name = "opensase-${var.pop_name}-pool"
  
  dynamic "origins" {
    for_each = var.instance_ips
    content {
      name    = "${var.pop_name}-${origins.key + 1}"
      address = origins.value
      enabled = true
      weight  = 1
    }
  }
  
  monitor = cloudflare_load_balancer_monitor.pop[0].id
  
  notification_email = "ops@opensase.io"
}

resource "cloudflare_load_balancer_monitor" "pop" {
  count = var.enable_geo_dns ? 1 : 0
  
  type     = lower(var.health_check.protocol)
  port     = var.health_check.port
  path     = var.health_check.path
  
  interval = 60
  retries  = 2
  timeout  = 5
  
  expected_codes = "200"
  
  header {
    header = "Host"
    values = ["${var.pop_name}.${var.domain}"]
  }
}

resource "cloudflare_load_balancer" "pop" {
  count = var.enable_geo_dns ? 1 : 0
  
  zone_id = data.cloudflare_zone.main.id
  name    = "${var.pop_name}.${var.domain}"
  
  default_pool_ids = [cloudflare_load_balancer_pool.pop[0].id]
  fallback_pool_id = cloudflare_load_balancer_pool.pop[0].id
  
  proxied = true
  
  session_affinity = "cookie"
  session_affinity_attributes {
    secure = "Always"
  }
}

# ===========================================
# Outputs
# ===========================================

output "dns_records" {
  value = {
    pop    = "${var.pop_name}.${var.domain}"
    api    = "api.${var.pop_name}.${var.domain}"
    health = cloudflare_healthcheck.pop.id
  }
}

output "load_balancer_id" {
  value = try(cloudflare_load_balancer.pop[0].id, null)
}
