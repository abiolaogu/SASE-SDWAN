# OpenSASE Edge - OVH Cloud Dedicated Server
# Terraform configuration for deploying edge nodes on OVH

terraform {
  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 0.34"
    }
  }
}

provider "ovh" {
  endpoint           = var.ovh_endpoint
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}

variable "ovh_endpoint" {
  description = "OVH API endpoint"
  type        = string
  default     = "ovh-eu"
}

variable "ovh_application_key" {
  description = "OVH Application Key"
  type        = string
  sensitive   = true
}

variable "ovh_application_secret" {
  description = "OVH Application Secret"
  type        = string
  sensitive   = true
}

variable "ovh_consumer_key" {
  description = "OVH Consumer Key"
  type        = string
  sensitive   = true
}

variable "datacenter" {
  description = "OVH datacenter code"
  type        = string
  default     = "gra"  # Gravelines
}

variable "server_service_names" {
  description = "Service names of already-ordered dedicated servers"
  type        = list(string)
  default     = []
}

# Note: OVH dedicated servers must be ordered separately
# This manages already-provisioned servers

data "ovh_dedicated_server" "edge" {
  count        = length(var.server_service_names)
  service_name = var.server_service_names[count.index]
}

# Installation Template
resource "ovh_me_installation_template" "opensase_edge" {
  base_template_name = "ubuntu2204-server_64"
  template_name      = "opensase-edge-template"
  
  customization {
    custom_hostname = "opensase-edge"
  }
}

# vRack Private Network (if using vRack)
variable "vrack_service_name" {
  description = "vRack service name for private networking"
  type        = string
  default     = ""
}

# Outputs
output "edge_servers" {
  description = "Edge server details"
  value = [for s in data.ovh_dedicated_server.edge : {
    name = s.name
    ip   = s.ip
    dc   = s.datacenter
  }]
}
