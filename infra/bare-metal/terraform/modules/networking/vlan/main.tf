# OBMO VLAN Configuration Module

variable "pop_name" {
  type = string
}

variable "provider_type" {
  type = string
}

variable "vlans" {
  description = "VLANs to create"
  type = map(object({
    id          = number
    name        = string
    subnet      = string
    gateway     = optional(string)
    description = optional(string)
  }))
  default = {}
}

# ===========================================
# Default VLAN Structure
# ===========================================

locals {
  default_vlans = {
    data_plane = {
      id          = 100
      name        = "${var.pop_name}-data"
      subnet      = "10.100.0.0/24"
      gateway     = "10.100.0.1"
      description = "VPP data plane traffic"
    }
    control_plane = {
      id          = 200
      name        = "${var.pop_name}-control"
      subnet      = "10.200.0.0/24"
      gateway     = "10.200.0.1"
      description = "FlexiWAN control plane"
    }
    management = {
      id          = 300
      name        = "${var.pop_name}-mgmt"
      subnet      = "10.250.0.0/24"
      gateway     = "10.250.0.1"
      description = "Management and monitoring"
    }
  }
  
  vlans = length(var.vlans) > 0 ? var.vlans : local.default_vlans
}

# ===========================================
# VLAN Configuration File
# ===========================================

resource "local_file" "vlan_config" {
  filename = "${path.module}/generated/${var.pop_name}-vlans.json"
  
  content = jsonencode({
    pop_name = var.pop_name
    provider = var.provider_type
    vlans    = local.vlans
  })
}

# ===========================================
# Network Interface Configuration
# ===========================================

resource "local_file" "netplan_config" {
  filename = "${path.module}/generated/${var.pop_name}-netplan.yaml"
  
  content = yamlencode({
    network = {
      version = 2
      vlans = { for name, vlan in local.vlans :
        "vlan${vlan.id}" => {
          id   = vlan.id
          link = "bond0"
          addresses = ["${vlan.gateway}/24"]
          mtu  = 9000
        }
      }
    }
  })
}

# ===========================================
# VPP VLAN Commands
# ===========================================

resource "local_file" "vpp_vlan_commands" {
  filename = "${path.module}/generated/${var.pop_name}-vpp-vlans.exec"
  
  content = <<-EOF
# VPP VLAN Configuration for ${var.pop_name}

%{ for name, vlan in local.vlans ~}
# ${vlan.description}
create sub-interface bond0 ${vlan.id}
set interface state bond0.${vlan.id} up
set interface ip address bond0.${vlan.id} ${vlan.gateway}/24

%{ endfor ~}
EOF
}

# ===========================================
# Outputs
# ===========================================

output "vlans" {
  value = local.vlans
}

output "vlan_config_path" {
  value = local_file.vlan_config.filename
}

output "netplan_path" {
  value = local_file.netplan_config.filename
}

output "vpp_vlan_script" {
  value = local_file.vpp_vlan_commands.filename
}
