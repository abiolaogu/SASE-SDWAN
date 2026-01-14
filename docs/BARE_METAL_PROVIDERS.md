# OpenSASE Bare Metal Provider Guide

## Overview

OpenSASE uses dedicated bare metal servers for maximum performance. **NO hyperscalers (AWS/Azure/GCP)** - only dedicated hardware with DPDK-compatible NICs.

## Provider Tiers

### Tier 1 - Global Coverage (100+ Gbps)

| Provider | Coverage | NIC Options | BGP Support |
|----------|----------|-------------|-------------|
| **Equinix Metal** | Global (30+ metros) | 2x100G Mellanox CX6 | ✅ Native |
| **Leaseweb** | Global (25+ DCs) | 2x25G + 1x100G | ✅ Via API |

### Tier 2 - Regional (25-100 Gbps)

| Provider | Coverage | NIC Options | Price/Month |
|----------|----------|-------------|-------------|
| **OVH Cloud** | EU/NA/APAC | 2x25G Intel XXV710 | $200-800 |
| **Hetzner** | EU (DE/FI) | 2x10G Intel X710 | $100-200 |
| **Scaleway** | EU (FR/NL/PL) | 2x25G-100G | $150-400 |
| **PhoenixNAP** | NA (4 DCs) | 2x25G-100G | $300-600 |

## Server Requirements

### Minimum Specs
- **CPU**: 32+ cores (AMD EPYC or Intel Xeon)
- **RAM**: 128+ GB DDR4/DDR5
- **NIC**: DPDK-compatible (see below)
- **Storage**: 2x NVMe SSD (RAID1)

### Supported NICs
| Vendor | Model | Speed | DPDK Driver |
|--------|-------|-------|-------------|
| Intel | X710 | 10G | i40e |
| Intel | XXV710 | 25G | i40e |
| Intel | XL710 | 40G | i40e |
| Intel | E810 | 100G | ice |
| Mellanox | ConnectX-5 | 100G | mlx5 |
| Mellanox | ConnectX-6 | 200G | mlx5 |

## Provider-Specific Configuration

### Equinix Metal
```hcl
module "pop_nyc" {
  source = "./providers/equinix"
  
  pop_config = {
    name           = "nyc1"
    metro          = "ny"
    environment    = "production"
    controller_url = "https://manage.opensase.io"
    activation_key = var.flexiwan_token
  }
  
  project_id       = var.equinix_project_id
  high_performance = true  # n3.xlarge.x86 (100G)
  enable_ha        = true
}
```

**Server Plans:**
- `n3.xlarge.x86`: 32 cores, 512GB RAM, 2x100GbE Mellanox CX6 ($4.50/hr)
- `m3.large.x86`: 32 cores, 256GB RAM, 2x25GbE Intel XXV710 ($2.50/hr)

### OVH Cloud
```hcl
module "pop_lon" {
  source = "./providers/ovh"
  
  pop_config = {
    name           = "lon1"
    datacenter     = "uk-1"
    environment    = "production"
    controller_url = "https://manage.opensase.io"
    activation_key = var.flexiwan_token
  }
  
  ovh_service_name   = "ns12345.ip-1-2-3.eu"
  vrack_service_name = "pn-12345"
}
```

### Hetzner
```hcl
module "pop_fra" {
  source = "./providers/hetzner"
  
  pop_config = {
    name           = "fra1"
    location       = "fsn1"
    environment    = "production"
    controller_url = "https://manage.opensase.io"
    activation_key = var.flexiwan_token
    network_id     = 10
  }
  
  robot_user     = var.hetzner_robot_user
  robot_password = var.hetzner_robot_password
  ssh_public_key = var.ssh_public_key
}
```

**Note:** Hetzner dedicated servers use Robot API, not hcloud.

### PhoenixNAP
```hcl
module "pop_phx" {
  source = "./providers/phoenixnap"
  
  pop_config = {
    name           = "phx1"
    location       = "PHX"
    environment    = "production"
    controller_url = "https://manage.opensase.io"
    activation_key = var.flexiwan_token
    network_id     = 20
  }
  
  high_performance = true  # s2.c2.medium (100G)
  enable_ha        = true
}
```

## Deployment Priority

1. **Phase 1**: Equinix Metal (NYC, LON, AMS, SIN, TOK)
2. **Phase 2**: OVH/Hetzner (EU expansion)
3. **Phase 3**: PhoenixNAP/Leaseweb (NA expansion)
4. **Phase 4**: Scaleway (EU peering optimization)

## Cost Comparison

| Provider | 32+ cores | 25G NIC | 100G NIC |
|----------|-----------|---------|----------|
| Equinix | $1,800/mo | - | $3,200/mo |
| OVH | $200/mo | $400/mo | $800/mo |
| Hetzner | $100/mo | $200/mo | Custom |
| Scaleway | $170/mo | $280/mo | $500/mo |
| PhoenixNAP | $2,300/mo | - | $3,900/mo |

## Environment Variables

```bash
# Equinix Metal
export METAL_AUTH_TOKEN="..."
export EQUINIX_PROJECT_ID="..."

# OVH
export OVH_APPLICATION_KEY="..."
export OVH_APPLICATION_SECRET="..."
export OVH_CONSUMER_KEY="..."

# Hetzner
export HETZNER_ROBOT_USER="..."
export HETZNER_ROBOT_PASSWORD="..."
export HCLOUD_TOKEN="..."

# Scaleway
export SCW_ACCESS_KEY="..."
export SCW_SECRET_KEY="..."
export SCW_DEFAULT_PROJECT_ID="..."

# PhoenixNAP
export PNAP_CLIENT_ID="..."
export PNAP_CLIENT_SECRET="..."

# Leaseweb
export LEASEWEB_API_KEY="..."

# FlexiWAN
export FLEXIWAN_TOKEN="..."

# SSH
export SSH_PUBLIC_KEY="$(cat ~/.ssh/opensase.pub)"
```

## Single Command Deploy

```bash
./infra/bare-metal/scripts/deploy-pop.sh equinix pop-nyc ny --plan n3.xlarge.x86 --bgp
./infra/bare-metal/scripts/deploy-pop.sh hetzner pop-fra fsn1 --plan SX134
./infra/bare-metal/scripts/deploy-pop.sh phoenixnap pop-phx PHX --plan s2.c2.medium --ha
```

## Target Performance

| Metric | Target |
|--------|--------|
| Line Rate | 100+ Gbps |
| Latency | <5μs per hop |
| Deploy Time | <15 minutes |
| Availability | 99.99% |
