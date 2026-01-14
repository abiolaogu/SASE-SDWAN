# OpenSASE PoP Module - Variables

# ===========================================
# Required Variables
# ===========================================

variable "pop_name" {
  description = "Name of the PoP (e.g., pop-nyc, pop-ldn)"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.pop_name))
    error_message = "PoP name must be lowercase alphanumeric with hyphens, 3-21 characters."
  }
}

variable "provider" {
  description = "Cloud provider (aws, gcp, azure, equinix, vultr, hetzner)"
  type        = string
  
  validation {
    condition     = contains(["aws", "gcp", "azure", "equinix", "vultr", "hetzner"], var.provider)
    error_message = "Provider must be one of: aws, gcp, azure, equinix, vultr, hetzner."
  }
}

variable "region" {
  description = "Cloud region for deployment"
  type        = string
}

variable "flexiwan_token" {
  description = "FlexiWAN device registration token"
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key for instance access"
  type        = string
}

# ===========================================
# Optional Variables - Compute
# ===========================================

variable "environment" {
  description = "Environment (production, staging, development)"
  type        = string
  default     = "production"
}

variable "instance_size" {
  description = "Instance size (small, medium, large, xlarge, metal)"
  type        = string
  default     = "medium"
  
  validation {
    condition     = contains(["small", "medium", "large", "xlarge", "metal"], var.instance_size)
    error_message = "Instance size must be one of: small, medium, large, xlarge, metal."
  }
}

variable "instance_count" {
  description = "Number of instances (for HA)"
  type        = number
  default     = 2
  
  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 10
    error_message = "Instance count must be between 1 and 10."
  }
}

variable "vpp_worker_cores" {
  description = "Number of VPP worker cores"
  type        = number
  default     = 4
}

# ===========================================
# Optional Variables - Network
# ===========================================

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.100.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public subnet CIDR"
  type        = string
  default     = "10.100.1.0/24"
}

variable "private_subnet_cidr" {
  description = "Private subnet CIDR"
  type        = string
  default     = "10.100.10.0/24"
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed for SSH access"
  type        = string
  default     = "0.0.0.0/0"
}

variable "monitoring_cidr" {
  description = "CIDR for monitoring access"
  type        = string
  default     = "10.0.0.0/8"
}

# ===========================================
# Optional Variables - DNS
# ===========================================

variable "domain" {
  description = "Base domain for PoP DNS"
  type        = string
  default     = "opensase.io"
}

variable "enable_dns" {
  description = "Enable DNS record creation"
  type        = bool
  default     = true
}

variable "enable_geo_dns" {
  description = "Enable GeoDNS load balancing"
  type        = bool
  default     = true
}

# ===========================================
# Optional Variables - FlexiWAN
# ===========================================

variable "flexiwan_url" {
  description = "FlexiWAN management URL"
  type        = string
  default     = "https://manage.opensase.io"
}

# ===========================================
# Optional Variables - Features
# ===========================================

variable "enable_suricata" {
  description = "Enable Suricata IPS"
  type        = bool
  default     = true
}

variable "enable_envoy" {
  description = "Enable Envoy L7 Gateway"
  type        = bool
  default     = true
}

variable "enable_monitoring" {
  description = "Enable monitoring integration"
  type        = bool
  default     = true
}

variable "grafana_url" {
  description = "Grafana URL for dashboards"
  type        = string
  default     = "https://grafana.opensase.io"
}

variable "prometheus_url" {
  description = "Prometheus URL for metrics"
  type        = string
  default     = "https://prometheus.opensase.io"
}

# ===========================================
# Optional Variables - Ansible
# ===========================================

variable "generate_inventory" {
  description = "Generate Ansible inventory file"
  type        = bool
  default     = true
}

variable "ssh_private_key_path" {
  description = "Path to SSH private key for Ansible"
  type        = string
  default     = "~/.ssh/opensase"
}

# ===========================================
# Optional Variables - Tags
# ===========================================

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}
