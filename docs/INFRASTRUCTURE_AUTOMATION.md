# OpenSASE Infrastructure Automation (OSIA)

## Overview

Deploy OpenSASE PoPs globally with a single command in under 15 minutes.

## Quick Start

```bash
# Deploy to AWS US East
./infra/scripts/deploy-pop.sh pop-nyc aws us-east-1

# Deploy to GCP Europe
./infra/scripts/deploy-pop.sh pop-ldn gcp europe-west2

# Deploy to Hetzner
./infra/scripts/deploy-pop.sh pop-hel hetzner fsn1
```

## Architecture

```
                            ┌─────────────────────┐
                            │   deploy-pop.sh     │
                            │   Single Command    │
                            └──────────┬──────────┘
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
        ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
        │   Terraform    │    │    Ansible     │    │   Cloudflare   │
        │  Infrastructure│    │  Configuration │    │      DNS       │
        └────────────────┘    └────────────────┘    └────────────────┘
                 │                     │                     │
    ┌────────────┼────────────┐        │                     │
    ▼            ▼            ▼        ▼                     ▼
 ┌──────┐   ┌──────┐   ┌──────┐   ┌──────────┐         ┌──────────┐
 │ AWS  │   │ GCP  │   │Azure │   │VPP/Flexi │         │ GeoDNS   │
 │ EC2  │   │ GCE  │   │  VM  │   │ Suricata │         │ Health   │
 └──────┘   └──────┘   └──────┘   └──────────┘         └──────────┘
```

## Supported Providers

| Provider | Regions | Instance Types |
|----------|---------|----------------|
| AWS | All | c6i.xlarge - c6i.8xlarge |
| GCP | All | c2-standard-4 - c2-standard-30 |
| Azure | All | Standard_F4s_v2 - Standard_F32s_v2 |
| Hetzner | EU, US | cpx31 - ccx53 |

## Prerequisites

### Environment Variables

```bash
# AWS
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

# GCP
export GOOGLE_APPLICATION_CREDENTIALS=...

# Azure
export ARM_SUBSCRIPTION_ID=...
export ARM_TENANT_ID=...
export ARM_CLIENT_ID=...
export ARM_CLIENT_SECRET=...

# Hetzner
export HCLOUD_TOKEN=...

# Common
export FLEXIWAN_TOKEN=...
export SSH_PUBLIC_KEY="$(cat ~/.ssh/opensase.pub)"
```

### Tools

- Terraform >= 1.5.0
- Ansible >= 2.14
- jq

## Directory Structure

```
infra/
├── terraform/
│   ├── main.tf              # Root module
│   ├── modules/
│   │   ├── vpc/             # Network (AWS/GCP/Azure/Hetzner)
│   │   ├── compute/         # Instances
│   │   ├── security/        # Firewall rules
│   │   └── dns/             # Cloudflare DNS
│   ├── templates/
│   │   └── user_data.sh.tpl # Bootstrap script
│   └── environments/
│       ├── production/
│       └── staging/
├── ansible/
│   ├── playbooks/
│   │   └── deploy-pop.yml   # Main playbook
│   ├── roles/
│   │   ├── vpp/             # VPP installation
│   │   ├── flexiedge/       # FlexiEdge setup
│   │   ├── suricata/        # IPS setup
│   │   └── monitoring/      # Metrics agents
│   └── inventory/           # Generated per-PoP
└── scripts/
    └── deploy-pop.sh        # Single command deploy
```

## Deployment Time

| Phase | Duration |
|-------|----------|
| Terraform Init | ~30s |
| Infrastructure Provisioning | ~3-5 min |
| SSH Ready | ~1-2 min |
| Ansible Configuration | ~5-8 min |
| **Total** | **~10-15 min** |

## Commands

### Deploy

```bash
./infra/scripts/deploy-pop.sh pop-nyc aws us-east-1
```

### Destroy

```bash
./infra/scripts/deploy-pop.sh pop-nyc aws us-east-1 --destroy
```

### Status

```bash
cd infra/terraform
terraform show
```

## Outputs

After deployment:
- DNS: `pop-nyc.opensase.io`
- Health: `https://pop-nyc.opensase.io/health`
- API: `https://api.pop-nyc.opensase.io`
