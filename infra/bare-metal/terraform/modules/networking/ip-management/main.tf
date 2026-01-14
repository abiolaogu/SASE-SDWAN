# OBMO IP Management Module

variable "pop_name" {
  type = string
}

variable "provider_type" {
  type = string
}

variable "public_ip_count" {
  description = "Number of public IPs to allocate"
  type        = number
  default     = 4
}

variable "anycast_ip_count" {
  description = "Number of anycast IPs"
  type        = number
  default     = 2
}

variable "private_subnet" {
  description = "Private subnet CIDR"
  type        = string
  default     = "10.100.0.0/24"
}

variable "management_subnet" {
  description = "Management subnet CIDR"
  type        = string
  default     = "10.250.0.0/24"
}

# ===========================================
# IP Allocation Plan
# ===========================================

locals {
  ip_plan = {
    public = {
      count = var.public_ip_count
      type  = "public_ipv4"
      usage = "Server public interfaces"
    }
    anycast = {
      count   = var.anycast_ip_count
      type    = "anycast_ipv4"
      usage   = "BGP anycast for HA"
      bgp     = true
    }
    private = {
      subnet  = var.private_subnet
      gateway = cidrhost(var.private_subnet, 1)
      usage   = "Internal PoP communication"
    }
    management = {
      subnet  = var.management_subnet
      gateway = cidrhost(var.management_subnet, 1)
      usage   = "SSH, monitoring, control plane"
    }
  }
  
  # Private IP assignments
  private_ips = [
    for i in range(10) : cidrhost(var.private_subnet, 10 + i)
  ]
  
  management_ips = [
    for i in range(10) : cidrhost(var.management_subnet, 10 + i)
  ]
}

# ===========================================
# IP Allocation Documentation
# ===========================================

resource "local_file" "ip_plan" {
  filename = "${path.module}/generated/${var.pop_name}-ip-plan.yaml"
  
  content = yamlencode({
    pop_name = var.pop_name
    provider = var.provider_type
    
    public_ips = {
      count = var.public_ip_count
      assignments = "Assigned by ${var.provider_type}"
    }
    
    anycast_ips = {
      count     = var.anycast_ip_count
      bgp_bound = true
      usage     = "Anycast for global load balancing"
    }
    
    private_network = {
      subnet      = var.private_subnet
      gateway     = local.ip_plan.private.gateway
      usable_ips  = local.private_ips
    }
    
    management_network = {
      subnet      = var.management_subnet
      gateway     = local.ip_plan.management.gateway
      usable_ips  = local.management_ips
    }
  })
}

# ===========================================
# Outputs
# ===========================================

output "ip_plan" {
  value = local.ip_plan
}

output "private_ips" {
  description = "Available private IPs"
  value       = local.private_ips
}

output "management_ips" {
  description = "Available management IPs"
  value       = local.management_ips
}

output "private_gateway" {
  value = local.ip_plan.private.gateway
}

output "management_gateway" {
  value = local.ip_plan.management.gateway
}
