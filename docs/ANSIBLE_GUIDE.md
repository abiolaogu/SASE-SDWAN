# OpenSASE Ansible Automation Guide

## Quick Start

Deploy a complete PoP with one command:

```bash
ansible-playbook -i inventory/production site.yaml -e pop_name=nyc1
```

**Target: Deploy in <15 minutes**

---

## Playbook Structure

```
infra/ansible/
├── site.yaml                    # Master playbook
├── inventory/
│   └── production               # PoP inventory
├── vars/
│   ├── common.yaml              # Shared variables
│   └── <pop_name>.yaml          # Per-PoP variables
├── roles/
│   ├── common/                  # Base system (2 min)
│   ├── kernel/                  # Performance tuning (1 min)
│   ├── vpp/                     # Data plane (4 min)
│   ├── bird/                    # BGP routing (1 min)
│   ├── wireguard/               # Mesh networking (1 min)
│   ├── security/                # Firewall, IDS (2 min)
│   └── monitoring/              # Exporters (1 min)
└── templates/
```

---

## Deployment Phases

| Phase | Role | Duration | Description |
|-------|------|----------|-------------|
| 1 | common | 2 min | Packages, DNS, NTP, sysctl |
| 2 | kernel | 1 min | Hugepages, CPU governor, DPDK |
| 3 | vpp | 4 min | VPP install and config |
| 4 | bird | 1 min | BGP daemon and sessions |
| 5 | wireguard | 1 min | Mesh key generation |
| 6 | security | 2 min | Suricata, iptables |
| 7 | monitoring | 1 min | Node/VPP exporters |
| **Total** | | **~12 min** | |

---

## Usage Examples

### Deploy single PoP

```bash
ansible-playbook -i inventory/production site.yaml \
  -e pop_name=fra1 \
  --limit pop_fra1
```

### Deploy with specific tags

```bash
# Only VPP and BIRD
ansible-playbook -i inventory/production site.yaml \
  -e pop_name=nyc1 \
  --tags "vpp,bird"

# Skip security
ansible-playbook -i inventory/production site.yaml \
  -e pop_name=nyc1 \
  --skip-tags security
```

### Validate deployment

```bash
ansible-playbook -i inventory/production site.yaml \
  -e pop_name=nyc1 \
  --tags validate
```

### Dry run

```bash
ansible-playbook -i inventory/production site.yaml \
  -e pop_name=nyc1 \
  --check --diff
```

---

## Per-PoP Configuration

Create `vars/<pop_name>.yaml`:

```yaml
pop_name: nyc1
pop_region: us-east

# VPP interfaces
vpp_interfaces:
  - name: TenGigabitEthernet0
    pci: "0000:18:00.0"
    workers: [1, 2]
  - name: TenGigabitEthernet1
    pci: "0000:18:00.1"
    workers: [3]

# BGP sessions
ixp_sessions:
  - name: "Equinix NYC"
    neighbor: 198.32.124.1
    asn: 19754
    type: routeserver

# WireGuard mesh
wg_local_ip: 100.64.1.1
wg_peers:
  - name: fra1
    public_key: "aBcDeFg..."
    endpoint: "fra1.opensase.io:51820"
    allowed_ips: ["100.64.2.0/24"]
```

---

## Role Details

### common
- Hostname, DNS, NTP
- Package installation
- sysctl tuning
- File limits
- SSH hardening

### kernel
- 1G hugepages
- Disable THP
- CPU performance governor
- Disable C-states
- DPDK module loading

### vpp
- VPP installation from fd.io
- startup.conf generation
- Interface binding
- WireGuard creation
- Service enablement

### bird
- BIRD 2 installation
- Main config generation
- RPKI configuration
- IXP session configs
- Validation

### wireguard
- Key generation
- Mesh config
- VPP integration
- Peer management

### security
- iptables rules
- Suricata IDS
- Rule updates
- fail2ban

### monitoring
- Node Exporter
- VPP Exporter
- BIRD metrics
- Textfile collector

---

## Troubleshooting

### VPP not starting

```bash
# Check logs
journalctl -u vpp -n 100

# Verify hugepages
cat /proc/meminfo | grep Huge

# Check DPDK binding
dpdk-devbind --status
```

### BGP sessions down

```bash
# Check BIRD
birdc show protocols

# Check neighbor reachability
ping <neighbor_ip>

# View logs
tail -f /var/log/bird/bird.log
```

### Ansible connection issues

```bash
# Test connectivity
ansible all -i inventory/production -m ping

# Verbose mode
ansible-playbook site.yaml -vvv
```

---

## Verification

After deployment, verify:

```bash
# VPP interfaces
vppctl show interface

# BGP sessions
birdc show protocols

# WireGuard tunnels
vppctl show wireguard

# Metrics
curl http://localhost:9100/metrics
curl http://localhost:9482/metrics
```
