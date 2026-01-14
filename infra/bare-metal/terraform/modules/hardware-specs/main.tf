# OpenSASE Hardware Specifications Module
# Defines 100+ Gbps capable bare metal configurations

# ===========================================
# Hardware Spec Tiers
# ===========================================

locals {
  # Minimum requirements for 100 Gbps PoP
  min_specs = {
    cores  = 32
    ram_gb = 128
    nic_speed_gbps = 100
  }
  
  # ===========================================
  # DPDK-Compatible NICs
  # ===========================================
  dpdk_nics = {
    intel_x710 = {
      vendor     = "Intel"
      model      = "X710"
      speed_gbps = 10
      ports      = 4
      driver     = "i40e"
      dpdk_pmd   = "net_i40e"
    }
    intel_xxv710 = {
      vendor     = "Intel"
      model      = "XXV710"
      speed_gbps = 25
      ports      = 2
      driver     = "i40e"
      dpdk_pmd   = "net_i40e"
    }
    intel_xl710 = {
      vendor     = "Intel"
      model      = "XL710"
      speed_gbps = 40
      ports      = 2
      driver     = "i40e"
      dpdk_pmd   = "net_i40e"
    }
    intel_e810 = {
      vendor     = "Intel"
      model      = "E810"
      speed_gbps = 100
      ports      = 2
      driver     = "ice"
      dpdk_pmd   = "net_ice"
    }
    mellanox_cx5 = {
      vendor     = "Mellanox/NVIDIA"
      model      = "ConnectX-5"
      speed_gbps = 100
      ports      = 2
      driver     = "mlx5_core"
      dpdk_pmd   = "net_mlx5"
    }
    mellanox_cx6 = {
      vendor     = "Mellanox/NVIDIA"
      model      = "ConnectX-6"
      speed_gbps = 200
      ports      = 2
      driver     = "mlx5_core"
      dpdk_pmd   = "net_mlx5"
    }
    mellanox_cx6_dx = {
      vendor     = "Mellanox/NVIDIA"
      model      = "ConnectX-6 Dx"
      speed_gbps = 100
      ports      = 2
      driver     = "mlx5_core"
      dpdk_pmd   = "net_mlx5"
      features   = ["crypto_offload", "ipsec_offload"]
    }
  }
  
  # ===========================================
  # Provider Server Specifications
  # ===========================================
  
  equinix_servers = {
    # 100 Gbps capable
    "n3.xlarge.x86" = {
      cores       = 32
      ram_gb      = 512
      storage     = "2x 480GB SSD + 2x 3.8TB NVMe"
      nic         = "2x 100GbE Mellanox CX6"
      nic_type    = "mellanox_cx6"
      total_gbps  = 200
      price_hour  = 4.50
    }
    "m3.large.x86" = {
      cores       = 32
      ram_gb      = 256
      storage     = "2x 480GB SSD + 2x 3.8TB NVMe"
      nic         = "2x 25GbE Intel XXV710"
      nic_type    = "intel_xxv710"
      total_gbps  = 50
      price_hour  = 2.50
    }
    "s3.xlarge.x86" = {
      cores       = 24
      ram_gb      = 192
      storage     = "2x 480GB SSD"
      nic         = "2x 25GbE Intel XXV710"
      nic_type    = "intel_xxv710"
      total_gbps  = 50
      price_hour  = 2.00
    }
  }
  
  ovh_servers = {
    "HGR-HCI-2" = {
      cores       = 48
      ram_gb      = 512
      storage     = "12x 3.84TB NVMe"
      nic         = "2x 25GbE Intel XXV710"
      nic_type    = "intel_xxv710"
      total_gbps  = 50
      price_month = 799
    }
    "HGR-SDS-2" = {
      cores       = 32
      ram_gb      = 256
      storage     = "24x 16TB HDD + 2x 960GB NVMe"
      nic         = "2x 25GbE"
      nic_type    = "intel_xxv710"
      total_gbps  = 50
      price_month = 649
    }
    "ADVANCE-6" = {
      cores       = 64
      ram_gb      = 512
      storage     = "2x 960GB NVMe"
      nic         = "2x 10GbE + 2x 25GbE"
      nic_type    = "intel_xxv710"
      total_gbps  = 70
      price_month = 449
    }
  }
  
  hetzner_servers = {
    "AX161" = {
      cores       = 64
      ram_gb      = 128
      storage     = "2x 1.92TB NVMe"
      nic         = "2x 10GbE Intel X710"
      nic_type    = "intel_x710"
      total_gbps  = 20
      price_month = 176
    }
    "AX102" = {
      cores       = 32
      ram_gb      = 128
      storage     = "2x 1.92TB NVMe"
      nic         = "2x 10GbE"
      nic_type    = "intel_x710"
      total_gbps  = 20
      price_month = 114
    }
    # Custom configs with 100G NICs available
    "AX161-CUSTOM" = {
      cores       = 64
      ram_gb      = 256
      storage     = "4x 3.84TB NVMe"
      nic         = "2x 100GbE Mellanox CX5"
      nic_type    = "mellanox_cx5"
      total_gbps  = 200
      price_month = 450
      custom      = true
    }
  }
  
  scaleway_servers = {
    "EM-L210E-NVME" = {
      cores       = 32
      ram_gb      = 128
      storage     = "2x 960GB NVMe"
      nic         = "2x 10GbE"
      nic_type    = "intel_x710"
      total_gbps  = 20
      price_month = 169
    }
    "EM-A210R-HDD" = {
      cores       = 32
      ram_gb      = 256
      storage     = "12x 16TB HDD"
      nic         = "2x 10GbE + 1x 25GbE"
      nic_type    = "intel_xxv710"
      total_gbps  = 45
      price_month = 279
    }
  }
  
  leaseweb_servers = {
    "BARE_METAL_XL" = {
      cores       = 48
      ram_gb      = 256
      storage     = "4x 1.92TB NVMe"
      nic         = "2x 10GbE + 1x 100GbE"
      nic_type    = "mellanox_cx5"
      total_gbps  = 120
      price_month = 599
    }
  }
  
  phoenixnap_servers = {
    "s2.c1.xlarge" = {
      cores       = 40
      ram_gb      = 256
      storage     = "2x 960GB NVMe"
      nic         = "4x 25GbE Intel XXV710"
      nic_type    = "intel_xxv710"
      total_gbps  = 100
      price_hour  = 3.28
    }
    "d2.c3.xlarge" = {
      cores       = 64
      ram_gb      = 512
      storage     = "2x 480GB SSD + 4x 3.84TB NVMe"
      nic         = "2x 100GbE Mellanox CX5"
      nic_type    = "mellanox_cx5"
      total_gbps  = 200
      price_hour  = 5.50
    }
  }
  
  # ===========================================
  # VPP Configuration by NIC Speed
  # ===========================================
  
  vpp_config_by_speed = {
    # 10-25 Gbps configuration
    "25" = {
      worker_cores   = 4
      rx_queues      = 4
      tx_queues      = 4
      rx_descriptors = 2048
      tx_descriptors = 2048
      buffers        = 128000
      socket_mem_mb  = 2048
      hugepages_gb   = 4
    }
    # 50 Gbps configuration
    "50" = {
      worker_cores   = 8
      rx_queues      = 8
      tx_queues      = 8
      rx_descriptors = 4096
      tx_descriptors = 4096
      buffers        = 256000
      socket_mem_mb  = 4096
      hugepages_gb   = 8
    }
    # 100+ Gbps configuration
    "100" = {
      worker_cores   = 16
      rx_queues      = 16
      tx_queues      = 16
      rx_descriptors = 8192
      tx_descriptors = 8192
      buffers        = 524288
      socket_mem_mb  = 8192
      hugepages_gb   = 16
    }
  }
  
  # ===========================================
  # Metro/Location Mapping
  # ===========================================
  
  metro_mapping = {
    # North America
    "nyc" = {
      equinix   = "ny"
      ovh       = "US-EAST-VA-1"
      hetzner   = "ash"
      phoenixnap = "PHX"
    }
    "lax" = {
      equinix   = "la"
      phoenixnap = "PHX"
    }
    "chi" = {
      equinix   = "ch"
      phoenixnap = "CHI"
    }
    # Europe
    "ams" = {
      equinix   = "am"
      ovh       = "EU-WEST-AM-1"
      hetzner   = "fsn1"
      scaleway  = "nl-ams"
    }
    "fra" = {
      equinix   = "fr"
      ovh       = "EU-CENTRAL-FR-1"
      hetzner   = "fsn1"
      scaleway  = "fr-par"
    }
    "ldn" = {
      equinix   = "ld"
      ovh       = "EU-WEST-UK-1"
    }
    # Asia Pacific
    "sin" = {
      equinix   = "sg"
      ovh       = "AP-SOUTH-SG-1"
    }
    "tok" = {
      equinix   = "ty"
    }
    "syd" = {
      equinix   = "sy"
      ovh       = "AP-SOUTH-AU-1"
    }
  }
}

# ===========================================
# Outputs
# ===========================================

output "dpdk_nics" {
  description = "Supported DPDK NICs"
  value       = local.dpdk_nics
}

output "min_specs" {
  description = "Minimum hardware requirements"
  value       = local.min_specs
}

output "equinix_servers" {
  description = "Equinix server configurations"
  value       = local.equinix_servers
}

output "ovh_servers" {
  description = "OVH server configurations"
  value       = local.ovh_servers
}

output "hetzner_servers" {
  description = "Hetzner server configurations"
  value       = local.hetzner_servers
}

output "vpp_config" {
  description = "VPP configuration by speed tier"
  value       = local.vpp_config_by_speed
}
