# Edge Deployment Guide

## Overview

This guide covers deploying OpenSASE edge devices with VPP data plane and flexiEdge SD-WAN agent integration.

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 50 GB SSD | 100+ GB NVMe |
| NICs | 2x 1GbE | 2x 10GbE+ |

### Software Requirements

- Ubuntu 22.04 LTS (or similar)
- Kernel 5.15+ with IOMMU support
- VFIO-PCI driver

## Deployment

### Automated Deployment

```bash
sudo ./scripts/edge/deploy-edge.sh \
    edge-nyc \
    https://manage.opensase.io \
    <activation-token>
```

This script:
1. Installs flexiEdge agent
2. Installs VPP with DPDK
3. Configures hugepages
4. Sets up systemd services
5. Connects to fleximanage

### Manual Deployment

#### 1. Install VPP

```bash
curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
sudo apt-get install -y vpp vpp-plugin-dpdk vpp-plugin-wireguard vpp-plugin-nat vpp-plugin-acl
```

#### 2. Configure Hugepages

```bash
# Allocate 1GB hugepages
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Make persistent
echo "vm.nr_hugepages = 1024" >> /etc/sysctl.conf
```

#### 3. Install flexiEdge

```bash
curl -sL https://deb.flexiwan.com/setup | sudo bash
sudo apt-get install -y flexiwan-router
```

#### 4. Configure Agent

```bash
cat > /etc/flexiwan/agent.conf << EOF
{
    "deviceName": "edge-nyc",
    "dataPlane": "vpp",
    "vppSocketPath": "/run/vpp/cli.sock",
    "managementUrl": "https://manage.opensase.io",
    "token": "<activation-token>"
}
EOF
```

#### 5. Start Services

```bash
sudo systemctl enable vpp flexiwan
sudo systemctl start vpp
sudo systemctl start flexiwan
```

## Network Configuration

### Interface Binding

Bind NICs to DPDK:

```bash
# Identify NICs
dpdk-devbind.py --status

# Bind to VFIO
sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00.0
sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00.1
```

### VPP Interface Assignment

In fleximanage UI:
1. Go to Devices → Select Device
2. Interfaces tab
3. Assign interfaces as WAN/LAN
4. Configure IP addresses

## Tunnel Configuration

### WireGuard Tunnels

Tunnels are automatically configured by fleximanage. VPP commands:

```bash
# Show WireGuard interfaces
vppctl show wireguard interface

# Show peers
vppctl show wireguard peer

# Show tunnel stats
vppctl show wireguard peer statistics
```

### Manual Tunnel (Testing)

```bash
# Create WireGuard interface
vppctl wireguard create listen-port 51820 private-key <base64-key>

# Add peer
vppctl wireguard peer add wg0 public-key <peer-key> endpoint <ip>:51820 allowed-ip 0.0.0.0/0
```

## Routing Configuration

### VRF Setup

```bash
# Create VRF
vppctl ip table add 1

# Add interface to VRF
vppctl set interface ip table eth1 1

# Add route in VRF
vppctl ip route add 10.0.0.0/8 via 192.168.1.1 table 1
```

### Policy-Based Routing

Configured via fleximanage policies:
- Application routing
- Segment routing
- Failover rules

## Performance Tuning

### CPU Isolation

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="isolcpus=1-7 nohz_full=1-7 rcu_nocbs=1-7"

# Update grub
sudo update-grub
sudo reboot
```

### VPP Worker Threads

```
# /etc/vpp/startup.conf
cpu {
    main-core 0
    corelist-workers 1-7
    scheduler-policy fifo
    scheduler-priority 50
}
```

### NUMA Optimization

```
# /etc/vpp/startup.conf
dpdk {
    socket-mem 1024,1024
    dev 0000:03:00.0 {
        num-rx-queues 4
        num-tx-queues 4
    }
}
```

## Monitoring

### VPP Statistics

```bash
# Interface stats
vppctl show interface

# Hardware counters
vppctl show hardware

# Error counters
vppctl show errors
```

### Health Endpoint

```bash
curl http://localhost:4789/health
```

Returns:
```json
{
    "status": "healthy",
    "vpp": "running",
    "flexiwan": "connected",
    "tunnels": 3,
    "uptime": 86400
}
```

## Troubleshooting

### Service Not Starting

```bash
# Check VPP
journalctl -u vpp -n 100

# Check flexiwan
journalctl -u flexiwan -n 100

# Check hugepages
cat /proc/meminfo | grep Huge
```

### DPDK Binding Issues

```bash
# Check IOMMU
dmesg | grep -i iommu

# Check NIC status
dpdk-devbind.py --status
```

### Connection Issues

```bash
# Test control plane
curl -k https://manage.opensase.io/api/health

# Check certificate
openssl s_client -connect manage.opensase.io:443
```

## Upgrades

### VPP Upgrade

```bash
sudo apt-get update
sudo apt-get install --only-upgrade vpp vpp-plugin-*
sudo systemctl restart vpp
```

### flexiEdge Upgrade

```bash
sudo apt-get update
sudo apt-get install --only-upgrade flexiwan-router
sudo systemctl restart flexiwan
```

## Backup & Recovery

### Configuration Backup

```bash
tar -czf edge-backup.tar.gz \
    /etc/vpp/ \
    /etc/flexiwan/ \
    /opt/opensase/
```

### Factory Reset

```bash
sudo systemctl stop flexiwan vpp
sudo rm -rf /etc/flexiwan/agent.conf
sudo rm -rf /var/lib/flexiwan/*
# Re-register device with new token
```
