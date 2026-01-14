# OBMO Production Deployment - NYC1 on Equinix Metal
# 100 Gbps PoP with BGP Anycast

terraform {
  required_version = ">= 1.5.0"
  
  backend "s3" {
    bucket         = "opensase-terraform-state"
    key            = "obmo/production/pop-nyc1-equinix/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "opensase-terraform-locks"
  }
}

# ===========================================
# Provider Configuration
# ===========================================

provider "equinix" {
  auth_token = var.equinix_auth_token
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ===========================================
# Variables
# ===========================================

variable "equinix_auth_token" {
  type      = string
  sensitive = true
}

variable "equinix_project_id" {
  type = string
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "cloudflare_zone_id" {
  type = string
}

variable "flexiwan_token" {
  type      = string
  sensitive = true
}

variable "ssh_public_key" {
  type = string
}

# ===========================================
# Equinix Metal Infrastructure
# ===========================================

module "equinix_servers" {
  source = "../../../providers/equinix"
  
  pop_name       = "nyc1"
  project_id     = var.equinix_project_id
  metro          = "ny"
  plan           = "n3.xlarge.x86"  # 100G Mellanox CX6
  instance_count = 2
  
  enable_bgp     = true
  bgp_asn        = 65100
  anycast_ips    = 4
  
  ssh_keys       = []
  controller_url = "https://manage.opensase.io"
  activation_key = var.flexiwan_token
  environment    = "production"
}

# ===========================================
# Pop Core Configuration
# ===========================================

module "pop_core" {
  source = "../../../modules/pop-core"
  
  pop_name       = "nyc1"
  provider_type  = "equinix"
  region         = "ny"
  server_plan    = "n3.xlarge.x86"
  instance_count = 2
  
  public_ips     = module.equinix_servers.public_ips
  private_ips    = module.equinix_servers.private_ips
  
  nic_type       = "mellanox_cx6"
  nic_speed_gbps = 200
  
  enable_bgp     = true
  bgp_asn        = 65100
  
  flexiwan_url   = "https://manage.opensase.io"
  flexiwan_token = var.flexiwan_token
  
  environment    = "production"
  
  tags = {
    cost_center = "infrastructure"
    team        = "network-ops"
  }
}

# ===========================================
# BGP Configuration
# ===========================================

module "bgp" {
  source = "../../../modules/networking/bgp"
  
  pop_name       = "nyc1"
  provider_type  = "equinix"
  server_ips     = module.equinix_servers.public_ips
  bgp_asn        = 65100
  anycast_prefixes = [module.equinix_servers.anycast_block.ipv4_address]
}

# ===========================================
# DNS Configuration
# ===========================================

module "dns" {
  source = "../../../modules/dns/cloudflare"
  
  pop_name   = "nyc1"
  zone_id    = var.cloudflare_zone_id
  domain     = "opensase.io"
  server_ips = module.equinix_servers.public_ips
  anycast_ips = [module.equinix_servers.anycast_block.ipv4_address]
}

# ===========================================
# Outputs
# ===========================================

output "pop_info" {
  value = module.pop_core.pop_info
}

output "servers" {
  value = module.pop_core.servers
}

output "bgp_config" {
  value = module.bgp.bgp_config
}

output "dns_records" {
  value = module.dns.dns_records
}

output "ssh_commands" {
  value = [for s in module.pop_core.servers : s.ssh]
}
