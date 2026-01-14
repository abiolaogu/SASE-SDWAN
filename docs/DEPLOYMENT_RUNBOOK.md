# OpenSASE PoP Deployment Runbook

## Quick Start

Deploy a complete PoP with one command:

```bash
./scripts/deploy-pop.sh nyc1 equinix production
```

**Target deployment time: <15 minutes**

---

## Prerequisites

### Environment Variables

```bash
export OPENSASE_CONTROLLER_URL="https://api.opensase.io"
export OPENSASE_ACTIVATION_KEY="your-activation-key"
export SSH_KEY_PATH="$HOME/.ssh/id_rsa"
```

### Required Tools

- Terraform >= 1.5
- Ansible >= 2.15
- SSH client

---

## Deployment Phases

| Phase | Duration | Components |
|-------|----------|------------|
| 1. Terraform | 2-3 min | Server provisioning |
| 2. SSH Wait | 1-2 min | Server boot |
| 3. Ansible | 10 min | Full stack deployment |
| 4. Validation | 1 min | Smoke tests |
| **Total** | **~15 min** | |

---

## Manual Deployment

### Step 1: Provision Infrastructure

```bash
cd infra/terraform/deployments/production
terraform apply -var="pop_name=nyc1"
```

### Step 2: Generate Inventory

```yaml
# inventory/dynamic/nyc1.yml
all:
  hosts:
    nyc1:
      ansible_host: 203.0.113.10
      ansible_user: root
      pop_name: nyc1
```

### Step 3: Run Ansible

```bash
cd infra/ansible
ansible-playbook -i inventory/dynamic/nyc1.yml \
  playbooks/deploy-pop.yml -e pop_name=nyc1
```

### Step 4: Verify

```bash
ansible-playbook -i inventory/dynamic/nyc1.yml \
  playbooks/verify-pop.yml -e pop_name=nyc1
```

---

## Playbook Tags

Run specific components:

```bash
# Only VPP and BIRD
ansible-playbook playbooks/deploy-pop.yml \
  -e pop_name=nyc1 --tags "vpp,bird"

# Skip security components
ansible-playbook playbooks/deploy-pop.yml \
  -e pop_name=nyc1 --skip-tags "security"

# Only validation
ansible-playbook playbooks/deploy-pop.yml \
  -e pop_name=nyc1 --tags "validate"
```

Available tags:
- `common` - Base system
- `kernel` - Kernel tuning
- `dpdk` - DPDK installation
- `vpp` - VPP data plane
- `bird` - BGP routing
- `wireguard` - Mesh tunnels
- `suricata` - IDS/IPS
- `envoy` - L7 proxy
- `flexiwan` - SD-WAN
- `monitoring` - Exporters
- `validate` - Smoke tests

---

## Troubleshooting

### Deployment Failed

```bash
# Check last deployment log
cat /var/log/opensase/deployment-*.json | tail -1 | jq

# Re-run with verbose
ansible-playbook playbooks/deploy-pop.yml \
  -e pop_name=nyc1 -vvv
```

### VPP Not Starting

```bash
# Check VPP logs
journalctl -u vpp -n 100

# Check hugepages
cat /proc/meminfo | grep Huge

# Manual start with debug
vpp -c /etc/vpp/startup.conf
```

### BGP Sessions Down

```bash
# Check BIRD status
birdc show status
birdc show protocols all

# Check connectivity to peer
ping <peer_ip>

# View BIRD logs
tail -f /var/log/bird/bird.log
```

### Smoke Tests Failed

```bash
# Re-run validation only
ansible-playbook playbooks/deploy-pop.yml \
  -e pop_name=nyc1 --tags validate

# Check individual services
vppctl show version
birdc show status
suricatasc -c uptime
```

---

## Rollback

```bash
# Rollback to previous VPP config
cp /etc/vpp/startup.conf.backup /etc/vpp/startup.conf
systemctl restart vpp

# Full rollback
ansible-playbook playbooks/deploy-pop.yml \
  -e pop_name=nyc1 --tags common,vpp,bird
```

---

## Post-Deployment

### Register with Portal

Automatic if `OPENSASE_ACTIVATION_KEY` is set, otherwise:

1. Go to https://portal.opensase.io/pops
2. Click "Add PoP"
3. Enter the public IP
4. Copy activation key to server

### Configure Peering

```bash
# Add IXP peer
birdc configure

# Check new sessions
birdc show protocols all
```

### Enable Monitoring

Metrics available at:
- Node Exporter: `http://<ip>:9100/metrics`
- VPP Exporter: `http://<ip>:9482/metrics`
