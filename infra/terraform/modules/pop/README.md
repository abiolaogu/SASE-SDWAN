# OpenSASE PoP Module

Reusable Terraform module for deploying OpenSASE Points of Presence (PoPs) across multiple cloud providers.

## Supported Providers

| Provider | Type | Regions |
|----------|------|---------|
| AWS | Public Cloud | All AWS regions |
| GCP | Public Cloud | All GCP regions |
| Azure | Public Cloud | All Azure regions |
| Equinix | Bare Metal | Global data centers |
| Vultr | Cloud/Bare Metal | Global locations |
| Hetzner | Cloud/Bare Metal | EU, US |

## Usage

### Basic Usage

```hcl
module "pop_nyc" {
  source = "./modules/pop"
  
  pop_name       = "pop-nyc"
  provider       = "aws"
  region         = "us-east-1"
  flexiwan_token = var.flexiwan_token
  ssh_public_key = var.ssh_public_key
}
```

### High Availability

```hcl
module "pop_ldn" {
  source = "./modules/pop"
  
  pop_name       = "pop-ldn"
  provider       = "gcp"
  region         = "europe-west2"
  instance_count = 3
  instance_size  = "large"
  
  flexiwan_token = var.flexiwan_token
  ssh_public_key = var.ssh_public_key
  
  enable_geo_dns = true
  enable_monitoring = true
}
```

### Bare Metal (Equinix)

```hcl
module "pop_ams" {
  source = "./modules/pop"
  
  pop_name       = "pop-ams"
  provider       = "equinix"
  region         = "am"  # Amsterdam
  instance_size  = "metal"
  instance_count = 2
  
  vpp_worker_cores = 16
  
  flexiwan_token = var.flexiwan_token
  ssh_public_key = var.ssh_public_key
}
```

## Instance Sizes

| Size | CPU | RAM | Use Case |
|------|-----|-----|----------|
| small | 4 | 8GB | Dev/test |
| medium | 8 | 16GB | Small branch |
| large | 16 | 32GB | Regional PoP |
| xlarge | 32 | 64GB | Major hub |
| metal | Dedicated | Full | High performance |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| pop_name | Name of the PoP | string | - | yes |
| provider | Cloud provider | string | - | yes |
| region | Cloud region | string | - | yes |
| flexiwan_token | FlexiWAN token | string | - | yes |
| ssh_public_key | SSH public key | string | - | yes |
| instance_size | Instance size | string | "medium" | no |
| instance_count | Number of instances | number | 2 | no |
| enable_dns | Enable DNS | bool | true | no |
| enable_monitoring | Enable monitoring | bool | true | no |

## Outputs

| Name | Description |
|------|-------------|
| pop_info | PoP deployment details |
| public_ips | List of public IPs |
| private_ips | List of private IPs |
| dns | DNS endpoints |
| ssh_commands | SSH connection commands |

## Deployment Time

Target: **< 15 minutes** for full PoP deployment

| Phase | Duration |
|-------|----------|
| Infrastructure | 3-5 min |
| Configuration | 5-8 min |
| Verification | 1-2 min |
