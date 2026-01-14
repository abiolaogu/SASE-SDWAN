# OpenSASE Global Provider Versions
# Pin all provider versions for consistency

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    # Major Cloud Providers
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
    
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
    
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.85"
    }
    
    # Bare Metal / Edge Providers
    equinix = {
      source  = "equinix/equinix"
      version = "~> 1.20"
    }
    
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.17"
    }
    
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.44"
    }
    
    # DNS / CDN Providers
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.20"
    }
    
    # Utility Providers
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# ===========================================
# Provider Configuration Guidelines
# ===========================================

# AWS: Use environment variables or ~/.aws/credentials
# export AWS_ACCESS_KEY_ID="..."
# export AWS_SECRET_ACCESS_KEY="..."
# export AWS_DEFAULT_REGION="us-east-1"

# GCP: Use service account JSON
# export GOOGLE_APPLICATION_CREDENTIALS="/path/to/sa.json"

# Azure: Use service principal
# export ARM_SUBSCRIPTION_ID="..."
# export ARM_TENANT_ID="..."
# export ARM_CLIENT_ID="..."
# export ARM_CLIENT_SECRET="..."

# Equinix: Use auth token
# export METAL_AUTH_TOKEN="..."

# Vultr: Use API key
# export VULTR_API_KEY="..."

# Hetzner: Use API token
# export HCLOUD_TOKEN="..."

# Cloudflare: Use API token
# export CLOUDFLARE_API_TOKEN="..."
