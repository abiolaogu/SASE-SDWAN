# OpenSASE Bare Metal Orchestrator (OBMO)
# Global Provider Configuration - DEDICATED SERVERS ONLY
# NO HYPERSCALERS (AWS/Azure/GCP) - Bare Metal Only

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    # ===========================================
    # TIER 1: Native Terraform Providers
    # ===========================================
    
    # Equinix Metal - Premium bare metal
    equinix = {
      source  = "equinix/equinix"
      version = "~> 1.20"
    }
    
    # Hetzner - Cost-effective European bare metal
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.44"
    }
    
    # Scaleway - Elastic Metal (EU)
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.34"
    }
    
    # OVH Cloud - Global dedicated servers
    ovh = {
      source  = "ovh/ovh"
      version = "~> 0.36"
    }
    
    # ===========================================
    # TIER 2: REST API Providers (null_resource)
    # ===========================================
    
    # For providers without native Terraform:
    # - Leaseweb (REST API)
    # - Voxility (REST API)
    # - ServerHub (REST API)
    # - ReliableSite (REST API)
    # - PhoenixNAP (BMC API)
    
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 1.18"
    }
    
    # ===========================================
    # Utility Providers
    # ===========================================
    
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    
    # Cloudflare for Anycast DNS
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.20"
    }
  }
  
  backend "s3" {
    bucket         = "opensase-bare-metal-state"
    key            = "obmo/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "opensase-terraform-locks"
  }
}

# ===========================================
# Provider Configurations
# ===========================================

# Equinix Metal
provider "equinix" {
  auth_token = var.equinix_auth_token
}

# Hetzner Cloud (for Robot API access)
provider "hcloud" {
  token = var.hetzner_token
}

# Scaleway
provider "scaleway" {
  access_key = var.scaleway_access_key
  secret_key = var.scaleway_secret_key
  project_id = var.scaleway_project_id
  region     = var.scaleway_region
}

# OVH
provider "ovh" {
  endpoint           = "ovh-eu"
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}

# REST API for custom providers
provider "restapi" {
  alias = "leaseweb"
  uri   = "https://api.leaseweb.com"
  
  headers = {
    X-Lsw-Auth = var.leaseweb_api_key
  }
  
  write_returns_object = true
}

provider "restapi" {
  alias = "phoenixnap"
  uri   = "https://api.phoenixnap.com/bmc/v1"
  
  headers = {
    Authorization = "Bearer ${var.phoenixnap_token}"
  }
  
  write_returns_object = true
}

# Cloudflare
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ===========================================
# Global Variables
# ===========================================

variable "equinix_auth_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "hetzner_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "hetzner_robot_user" {
  type      = string
  sensitive = true
  default   = ""
}

variable "hetzner_robot_password" {
  type      = string
  sensitive = true
  default   = ""
}

variable "scaleway_access_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "scaleway_secret_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "scaleway_project_id" {
  type    = string
  default = ""
}

variable "scaleway_region" {
  type    = string
  default = "fr-par"
}

variable "ovh_application_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "ovh_application_secret" {
  type      = string
  sensitive = true
  default   = ""
}

variable "ovh_consumer_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "leaseweb_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "phoenixnap_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "voxility_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
  default   = ""
}
