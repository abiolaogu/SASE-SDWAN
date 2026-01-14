# OpenSASE VPP 100 Gbps Deployment Guide

## Executive Summary

This guide walks through deploying the OpenSASE VPP Engine for **100 Gbps** throughput with **<5μs** latency on dedicated bare metal servers.

## Prerequisites

### Hardware Checklist

- [ ] 32+ core CPU (AMD EPYC 7003 / Intel Xeon 4th Gen)
- [ ] 128 GB DDR4-3200 RAM
- [ ] 2x 100GbE NICs (Mellanox ConnectX-6 or Intel E810)
- [ ] IOMMU enabled
- [ ] NUMA topology verified

### Software Checklist

- [ ] Ubuntu 22.04 LTS / RHEL 8+
- [ ] VPP 24.06+ installed
- [ ] DPDK 23.11+ (bundled with VPP)
- [ ] Hyperscan 5.4+ (optional, for IPS)
- [ ] TRex 3.00+ (for testing)

## Step-by-Step Deployment

### Step 1: Prepare the Host

```bash
# Clone the repository
git clone https://github.com/opensase/SASE-SDWAN.git
cd SASE-SDWAN/opensase-core

# Run host preparation (as root)
sudo ./vpp/scripts/prepare-vpp-host.sh \
    --nic1 0000:41:00.0 \
    --nic2 0000:41:00.1
```

This script will:
- Configure hugepages (64 GB)
- Set up GRUB for CPU isolation
- Bind NICs to VFIO-PCI
- Disable irqbalance
- Set CPU governor to performance

### Step 2: Reboot

```bash
sudo reboot
```

After reboot, verify:

```bash
# Check hugepages
cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
# Expected: 64

# Check CPU isolation
cat /sys/devices/system/cpu/isolated
# Expected: 4-31

# Check NICs
dpdk-devbind --status
# Expected: 0000:41:00.x bound to vfio-pci
```

### Step 3: Install OpenSASE VPP

```bash
# Run the installer
sudo ./vpp/scripts/install-opensase-vpp.sh
```

This will:
- Install VPP packages
- Build OpenSASE plugins
- Install configuration files
- Set up systemd service

### Step 4: Configure VPP

Edit `/etc/vpp/startup.conf`:

```
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    poll-sleep-usec 0
    startup-config /etc/vpp/setup.conf
}

cpu {
    main-core 0
    corelist-workers 4-19  # Adjust for your CPU
}

dpdk {
    dev 0000:41:00.0 {
        name wan0
        num-rx-queues 8
        num-tx-queues 8
    }
    dev 0000:41:00.1 {
        name lan0
        num-rx-queues 8
        num-tx-queues 8
    }
    socket-mem 8192,8192
}
```

Edit `/etc/vpp/setup.conf`:

```
# Enable interfaces
set interface state wan0 up
set interface state lan0 up

# Enable OpenSASE
set interface feature wan0 ip4-unicast opensase-tenant

# Configure tenants (example)
opensase tenant vni add vni 1000 tenant 1

# Configure WireGuard (example)
wireguard create listen-port 51820 private-key <KEY> src 203.0.113.10
```

### Step 5: Start VPP

```bash
# Start the service
sudo systemctl start opensase-vpp

# Check status
sudo systemctl status opensase-vpp

# View logs
tail -f /var/log/vpp/vpp.log
```

### Step 6: Verify Operation

```bash
# Connect to VPP CLI
sudo vppctl -s /run/vpp/cli.sock

# Check interfaces
show interface

# Check OpenSASE status
show opensase version
show opensase stats

# Check WireGuard
show wireguard interface
```

### Step 7: Run Benchmarks

```bash
# Quick health check
sudo ./vpp/tests/run-benchmark.sh sase 30

# Full benchmark suite (requires TRex)
python3 ./vpp/tests/benchmark_vpp.py --test all --duration 60
```

## Production Configuration

### Multi-Tenant Setup

```bash
# Add VXLAN VNI to tenant mappings
vppctl opensase tenant vni add vni 1000 tenant 1
vppctl opensase tenant vni add vni 1001 tenant 2
vppctl opensase tenant vni add vni 1002 tenant 3

# Add NAT pools per tenant
vppctl opensase nat pool tenant 1 address 203.0.113.1 ports 10000-40000
vppctl opensase nat pool tenant 2 address 203.0.113.2 ports 10000-40000
```

### WireGuard Mesh

```bash
# Create WireGuard interface
vppctl wireguard create listen-port 51820 private-key <KEY> src 203.0.113.10

# Add peers
vppctl wireguard peer add wg0 \
    public-key <LONDON_KEY> \
    endpoint 198.51.100.10:51820 \
    allowed-ip 10.0.0.0/8 \
    persistent-keepalive 25

vppctl wireguard peer add wg0 \
    public-key <TOKYO_KEY> \
    endpoint 192.0.2.10:51820 \
    allowed-ip 10.0.0.0/8 \
    persistent-keepalive 25
```

### High Availability

1. **Active-Passive**: Use VRRP with VPP on standby node
2. **Active-Active**: Configure ECMP with multiple PoPs
3. **Health Checks**: Use external monitoring with graceful failover

## Monitoring

### Prometheus Integration

VPP exports metrics via the stats segment. Use the VPP Prometheus exporter:

```bash
# Install exporter
pip install vpp-prometheus-exporter

# Run exporter
vpp-prometheus-exporter --socket /run/vpp/api.sock --port 9482
```

### Key Metrics to Monitor

| Metric | Alert Threshold |
|--------|-----------------|
| `vpp_interface_rx_packets` | Sustained drop |
| `vpp_interface_rx_errors` | > 0 |
| `vpp_node_clocks_per_packet` | > 1000 |
| `opensase_sessions_active` | > 8M |
| `opensase_packets_dropped` | > 0.001% |

### Grafana Dashboard

Import the provided dashboard from `docs/grafana/vpp_dashboard.json`.

## Troubleshooting

### VPP Won't Start

```bash
# Check for config errors
vpp -c /etc/vpp/startup.conf --check

# Check hugepages
cat /proc/meminfo | grep Huge

# Check DPDK bindings
dpdk-devbind --status
```

### Low Performance

```bash
# Check runtime stats
vppctl show runtime max

# Check for drops
vppctl show errors

# Check buffer usage
vppctl show buffers
```

### Connection Issues

```bash
# Check WireGuard status
vppctl show wireguard interface

# Test ping through tunnel
vppctl ping 10.200.0.2 source 10.200.0.1
```

## Maintenance

### Software Updates

```bash
# Stop VPP
sudo systemctl stop opensase-vpp

# Update packages
sudo apt update && sudo apt upgrade vpp vpp-plugin-*

# Rebuild plugins
cd opensase-core/vpp && make clean build install

# Start VPP
sudo systemctl start opensase-vpp
```

### Log Rotation

```bash
# /etc/logrotate.d/vpp
/var/log/vpp/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

## Quick Reference

```bash
# Service control
systemctl start/stop/restart opensase-vpp

# VPP CLI
vppctl -s /run/vpp/cli.sock

# Common commands
show interface
show runtime
show opensase stats
show wireguard interface

# Performance check
./vpp/tests/run-benchmark.sh sase 30
```

## Support

- Documentation: `/opensase-core/docs/`
- GitHub Issues: https://github.com/opensase/SASE-SDWAN/issues
- Slack: #opensase-vpp
