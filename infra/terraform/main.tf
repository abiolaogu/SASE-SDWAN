# OpenSASE Infrastructure Automation (OSIA)
# Terraform Root Module - Multi-Cloud PoP Deployment

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.44"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
  
  backend "s3" {
    bucket         = "opensase-terraform-state"
    key            = "global/pop/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

# ===========================================
# Variables
# ===========================================

variable "environment" {
  description = "Environment name (production, staging)"
  type        = string
  default     = "production"
}

variable "pop_name" {
  description = "Name of the PoP (e.g., pop-nyc, pop-ldn)"
  type        = string
}

variable "cloud_provider" {
  description = "Cloud provider (aws, gcp, azure, hetzner)"
  type        = string
}

variable "region" {
  description = "Cloud region for deployment"
  type        = string
}

variable "instance_type" {
  description = "Instance type/size"
  type        = string
  default     = "c6i.2xlarge"
}

variable "enable_ha" {
  description = "Enable high availability (multiple instances)"
  type        = bool
  default     = true
}

variable "instance_count" {
  description = "Number of instances for HA"
  type        = number
  default     = 2
}

variable "domain" {
  description = "Base domain for PoP"
  type        = string
  default     = "opensase.io"
}

variable "ssh_public_key" {
  description = "SSH public key for instance access"
  type        = string
}

variable "flexiwan_token" {
  description = "FlexiWAN registration token"
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ===========================================
# Local Variables
# ===========================================

locals {
  common_tags = merge(
    {
      Environment = var.environment
      Project     = "OpenSASE"
      PoP         = var.pop_name
      ManagedBy   = "Terraform"
      CreatedAt   = timestamp()
    },
    var.tags
  )
  
  # Instance type mapping across clouds
  instance_types = {
    aws = {
      small  = "c6i.xlarge"
      medium = "c6i.2xlarge"
      large  = "c6i.4xlarge"
      xlarge = "c6i.8xlarge"
    }
    gcp = {
      small  = "c2-standard-4"
      medium = "c2-standard-8"
      large  = "c2-standard-16"
      xlarge = "c2-standard-30"
    }
    azure = {
      small  = "Standard_F4s_v2"
      medium = "Standard_F8s_v2"
      large  = "Standard_F16s_v2"
      xlarge = "Standard_F32s_v2"
    }
    hetzner = {
      small  = "cpx31"
      medium = "cpx41"
      large  = "cpx51"
      xlarge = "ccx53"
    }
  }
}

# ===========================================
# VPC/Network Module
# ===========================================

module "vpc" {
  source = "./modules/vpc"
  
  cloud_provider = var.cloud_provider
  region         = var.region
  pop_name       = var.pop_name
  environment    = var.environment
  
  # Network configuration
  vpc_cidr           = "10.${index(["aws", "gcp", "azure", "hetzner"], var.cloud_provider) * 64}.0.0/16"
  public_subnet_cidr = "10.${index(["aws", "gcp", "azure", "hetzner"], var.cloud_provider) * 64}.1.0/24"
  private_subnet_cidr = "10.${index(["aws", "gcp", "azure", "hetzner"], var.cloud_provider) * 64}.10.0/24"
  
  tags = local.common_tags
}

# ===========================================
# Security Module
# ===========================================

module "security" {
  source = "./modules/security"
  
  cloud_provider = var.cloud_provider
  vpc_id         = module.vpc.vpc_id
  pop_name       = var.pop_name
  
  # Allow WireGuard, HTTPS, SSH
  allowed_ports = [
    { port = 22, protocol = "tcp", cidr = "0.0.0.0/0", description = "SSH" },
    { port = 443, protocol = "tcp", cidr = "0.0.0.0/0", description = "HTTPS" },
    { port = 51820, protocol = "udp", cidr = "0.0.0.0/0", description = "WireGuard" },
    { port = 4433, protocol = "tcp", cidr = "0.0.0.0/0", description = "FlexiWAN" },
    { port = 8080, protocol = "tcp", cidr = "10.0.0.0/8", description = "Internal API" },
  ]
  
  tags = local.common_tags
}

# ===========================================
# Compute Module
# ===========================================

module "compute" {
  source = "./modules/compute"
  
  cloud_provider = var.cloud_provider
  region         = var.region
  pop_name       = var.pop_name
  environment    = var.environment
  
  # Network
  vpc_id           = module.vpc.vpc_id
  subnet_id        = module.vpc.public_subnet_id
  security_group_id = module.security.security_group_id
  
  # Instance configuration
  instance_type  = var.instance_type
  instance_count = var.enable_ha ? var.instance_count : 1
  ssh_public_key = var.ssh_public_key
  
  # User data for bootstrapping
  user_data = templatefile("${path.module}/templates/user_data.sh.tpl", {
    pop_name       = var.pop_name
    flexiwan_url   = "https://manage.opensase.io"
    flexiwan_token = var.flexiwan_token
    environment    = var.environment
  })
  
  tags = local.common_tags
}

# ===========================================
# DNS Module
# ===========================================

module "dns" {
  source = "./modules/dns"
  
  domain         = var.domain
  pop_name       = var.pop_name
  instance_ips   = module.compute.public_ips
  enable_geo_dns = true
  
  # Health check configuration
  health_check = {
    path     = "/health"
    port     = 443
    protocol = "HTTPS"
  }
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  description = "PoP deployment information"
  value = {
    name        = var.pop_name
    provider    = var.cloud_provider
    region      = var.region
    environment = var.environment
  }
}

output "instance_ips" {
  description = "Public IPs of PoP instances"
  value       = module.compute.public_ips
}

output "private_ips" {
  description = "Private IPs of PoP instances"
  value       = module.compute.private_ips
}

output "dns_endpoint" {
  description = "DNS endpoint for the PoP"
  value       = "${var.pop_name}.${var.domain}"
}

output "ssh_command" {
  description = "SSH command to connect to instances"
  value       = [for ip in module.compute.public_ips : "ssh -i ~/.ssh/opensase ubuntu@${ip}"]
}

output "ansible_inventory" {
  description = "Ansible inventory entry"
  value = {
    pop_name = var.pop_name
    hosts    = module.compute.public_ips
    vars = {
      ansible_user = "ubuntu"
      flexiwan_token = var.flexiwan_token
    }
  }
  sensitive = true
}
