#!/bin/bash
# OBMO 100 Gbps Bootstrap Script
# Equinix Metal Bare Metal Server

set -euo pipefail

exec > >(tee /var/log/obmo-bootstrap.log) 2>&1

echo "================================================================"
echo "  OpenSASE Bare Metal Orchestrator (OBMO)"
echo "  100 Gbps PoP Bootstrap"
echo "================================================================"
echo "  PoP:         ${pop_name}"
echo "  Server:      ${server_index}/${server_count}"
echo "  Role:        ${is_primary ? "PRIMARY" : "SECONDARY"}"
echo "  NIC Type:    ${nic_type}"
echo "  NIC Speed:   ${nic_speed} Gbps"
echo "  BGP:         ${enable_bgp ? "ENABLED (ASN: ${bgp_asn})" : "DISABLED"}"
echo "================================================================"

export DEBIAN_FRONTEND=noninteractive

# ===========================================
# System Updates
# ===========================================

echo "[1/10] Updating system..."
apt-get update
apt-get upgrade -y

apt-get install -y \
    curl wget git jq htop iotop \
    net-tools tcpdump iperf3 ethtool \
    python3 python3-pip \
    pciutils lshw numactl hwloc \
    linux-tools-common linux-tools-generic

# ===========================================
# 100 Gbps Kernel Tuning
# ===========================================

echo "[2/10] Configuring kernel for 100 Gbps..."

cat > /etc/sysctl.d/99-obmo-100g.conf << 'SYSCTL'
# OBMO 100 Gbps Network Tuning
# =============================

# Core network settings
net.core.rmem_max = 2147483647
net.core.wmem_max = 2147483647
net.core.rmem_default = 536870912
net.core.wmem_default = 536870912
net.core.optmem_max = 536870912

# Netdev backlog for high packet rates
net.core.netdev_max_backlog = 2000000
net.core.netdev_budget = 100000
net.core.netdev_budget_usecs = 5000

# TCP tuning for 100G
net.ipv4.tcp_rmem = 4096 4194304 2147483647
net.ipv4.tcp_wmem = 4096 4194304 2147483647
net.ipv4.tcp_mem = 4194304 8388608 16777216
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3

# UDP tuning
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# IP forwarding
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# ARP settings
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384

# Hugepages (16GB for VPP)
vm.nr_hugepages = 8192
vm.hugetlb_shm_group = 0
vm.swappiness = 1

# Network hash sizes
net.core.rps_sock_flow_entries = 32768
SYSCTL

sysctl -p /etc/sysctl.d/99-obmo-100g.conf

# ===========================================
# Hugepages Setup (16GB)
# ===========================================

echo "[3/10] Configuring 16GB hugepages..."

mkdir -p /dev/hugepages
mount -t hugetlbfs nodev /dev/hugepages || true

cat >> /etc/fstab << 'EOF'
hugetlbfs /dev/hugepages hugetlbfs defaults,pagesize=2M 0 0
EOF

# ===========================================
# CPU Isolation for VPP Workers
# ===========================================

echo "[4/10] Configuring CPU isolation..."

# Get NUMA topology
NUMA_NODES=$(numactl --hardware | grep "available:" | awk '{print $2}')
echo "NUMA nodes detected: $NUMA_NODES"

# Isolate cores 2-17 for VPP workers (16 cores)
WORKER_CORES="2-$((2 + ${worker_cores} - 1))"
echo "Worker cores: $WORKER_CORES"

# Update GRUB for CPU isolation
if ! grep -q "isolcpus" /etc/default/grub; then
    sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"isolcpus=$WORKER_CORES nohz_full=$WORKER_CORES rcu_nocbs=$WORKER_CORES intel_iommu=on iommu=pt default_hugepagesz=2M hugepagesz=2M hugepages=8192 /" /etc/default/grub
    update-grub
fi

# ===========================================
# NIC Detection and DPDK Setup
# ===========================================

echo "[5/10] Detecting and configuring NICs..."

%{ if nic_type == "mellanox_cx5" || nic_type == "mellanox_cx6" }
# Mellanox ConnectX-5/6 Setup
echo "Configuring Mellanox NICs..."

# Install Mellanox OFED drivers
wget -q https://content.mellanox.com/ofed/MLNX_OFED-5.9-0.5.6.0/MLNX_OFED_LINUX-5.9-0.5.6.0-ubuntu22.04-x86_64.tgz -O /tmp/mlnx_ofed.tgz
cd /tmp && tar xzf mlnx_ofed.tgz
cd MLNX_OFED_LINUX-* && ./mlnxofedinstall --force --without-fw-update

# Enable SR-IOV
modprobe mlx5_core

# Detect Mellanox NICs
DPDK_NICS=$(lspci -d 15b3: | awk '{print $1}')
%{ endif }

%{ if nic_type == "intel_xxv710" || nic_type == "intel_x710" }
# Intel X710/XXV710 Setup
echo "Configuring Intel NICs..."

# Install DPDK and dependencies
apt-get install -y dpdk dpdk-dev dpdk-doc libdpdk-dev

# Load VFIO-PCI module
modprobe vfio-pci
echo "vfio-pci" >> /etc/modules-load.d/vfio.conf

# Detect Intel NICs
DPDK_NICS=$(lspci -d 8086:158b | awk '{print $1}')  # XXV710
if [ -z "$DPDK_NICS" ]; then
    DPDK_NICS=$(lspci -d 8086:1583 | awk '{print $1}')  # XL710
fi
if [ -z "$DPDK_NICS" ]; then
    DPDK_NICS=$(lspci -d 8086:1572 | awk '{print $1}')  # X710
fi
%{ endif }

%{ if nic_type == "intel_e810" }
# Intel E810 Setup
echo "Configuring Intel E810 100G NICs..."

modprobe ice
modprobe vfio-pci

DPDK_NICS=$(lspci -d 8086:1592 | awk '{print $1}')
%{ endif }

echo "Detected DPDK NICs: $DPDK_NICS"

# ===========================================
# Install VPP for 100 Gbps
# ===========================================

echo "[6/10] Installing VPP with 100 Gbps support..."

curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
apt-get install -y \
    vpp vpp-plugin-core vpp-plugin-dpdk \
    vpp-plugin-wireguard vpp-plugin-nat vpp-plugin-acl \
    vpp-dev vpp-api-python libvppinfra

# Configure VPP for 100 Gbps
cat > /etc/vpp/startup.conf << 'VPPCONF'
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    log /var/log/vpp/vpp.log
    full-coredump
    gid vpp
    exec /etc/vpp/startup.exec
}

api-trace {
    on
    nitems 5000
}

api-segment {
    gid vpp
}

socksvr {
    default
}

cpu {
    main-core 0
    corelist-workers ${worker_cores > 8 ? "2-17" : "2-9"}
    scheduler-policy fifo
    scheduler-priority 80
}

dpdk {
    dev default {
        num-rx-queues 16
        num-tx-queues 16
        num-rx-desc 8192
        num-tx-desc 8192
    }
    
    # Auto-bind DPDK NICs
    # dev 0000:XX:00.0
    # dev 0000:XX:00.1
    
    uio-driver vfio-pci
    socket-mem 8192,8192
    num-mbufs 524288
    no-multi-seg
    no-tx-checksum-offload
}

buffers {
    buffers-per-numa 524288
    default data-size 2048
    page-size 2M
}

statseg {
    socket-name /var/run/vpp/stats.sock
    size 512M
    per-node-counters on
}

plugins {
    plugin default { enable }
    plugin dpdk_plugin.so { enable }
    plugin wireguard_plugin.so { enable }
    plugin nat_plugin.so { enable }
    plugin acl_plugin.so { enable }
    plugin ping_plugin.so { enable }
}
VPPCONF

# Startup commands
cat > /etc/vpp/startup.exec << 'VPPEXEC'
comment { OBMO 100 Gbps VPP Configuration }

set interface state all up

comment { NAT configuration }
nat44 plugin enable sessions 1000000

comment { ICMP punt }
set punt ipv4 udp all
VPPEXEC

systemctl enable vpp

# ===========================================
# Install FlexiEdge
# ===========================================

echo "[7/10] Installing FlexiEdge..."

curl -sL https://deb.flexiwan.com/setup | bash
apt-get install -y flexiwan-router

mkdir -p /etc/flexiwan
cat > /etc/flexiwan/agent.conf << EOF
{
    "deviceName": "obmo-${pop_name}-${server_index}",
    "dataPlane": "vpp",
    "vppSocketPath": "/run/vpp/cli.sock",
    "managementUrl": "${controller_url}",
    "token": "${activation_key}",
    "logLevel": "info",
    "telemetryInterval": 15,
    "features": {
        "sdwan": true,
        "firewall": true,
        "nat": true,
        "qos": true,
        "wireguard": true
    }
}
EOF

systemctl enable flexiwan

# ===========================================
# BGP Configuration (BIRD)
# ===========================================

%{ if enable_bgp }
echo "[8/10] Configuring BGP..."

apt-get install -y bird2

cat > /etc/bird/bird.conf << 'BIRDCONF'
router id from "lo";

log syslog all;
log stderr { error, fatal };

protocol device {
    scan time 10;
}

protocol direct {
    ipv4;
    ipv6;
    interface "lo";
}

protocol kernel {
    ipv4 {
        export all;
        import none;
    };
    learn;
    persist;
}

protocol kernel {
    ipv6 {
        export all;
        import none;
    };
    learn;
    persist;
}

# Local AS
define MY_AS = ${bgp_asn};

# BGP to Equinix Metal
protocol bgp equinix_v4 {
    local as MY_AS;
    neighbor 169.254.255.1 as 65530;
    multihop 2;
    password "equinix_bgp_md5";
    
    ipv4 {
        import none;
        export filter {
            if net ~ [ 0.0.0.0/0{24,32} ] then accept;
            reject;
        };
    };
}

protocol bgp equinix_v6 {
    local as MY_AS;
    neighbor 2604:1380:4641:c500::1 as 65530;
    multihop 2;
    password "equinix_bgp_md5";
    
    ipv6 {
        import none;
        export filter {
            if net ~ [ ::/0{48,128} ] then accept;
            reject;
        };
    };
}
BIRDCONF

systemctl enable bird
%{ else }
echo "[8/10] Skipping BGP configuration..."
%{ endif }

# ===========================================
# Install Suricata IPS
# ===========================================

echo "[9/10] Installing Suricata IPS..."

add-apt-repository -y ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata suricata-update

suricata-update

# Configure for high-throughput
cat > /etc/suricata/suricata-local.yaml << 'SURICONF'
%YAML 1.1
---
max-pending-packets: 65535
default-packet-size: 1514

runmode: workers

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    mmap-locked: yes
    ring-size: 200000
    buffer-size: 1048576
SURICONF

systemctl enable suricata

# ===========================================
# Health Check Service
# ===========================================

echo "[10/10] Setting up health check..."

cat > /opt/obmo-health.py << 'HEALTHPY'
#!/usr/bin/env python3
import http.server
import json
import subprocess
import socketserver
import os

PORT = 8080

class HealthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging
        
    def do_GET(self):
        if self.path == '/health':
            health = self.get_health()
            code = 200 if health['status'] == 'healthy' else 503
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(health, indent=2).encode())
        elif self.path == '/metrics':
            self.send_metrics()
        else:
            self.send_response(404)
            self.end_headers()
    
    def get_health(self):
        services = {
            'vpp': self.check_service('vpp'),
            'flexiwan': self.check_service('flexiwan'),
            'suricata': self.check_service('suricata'),
            'bird': self.check_service('bird')
        }
        
        # Check VPP interfaces
        vpp_ok = False
        try:
            result = subprocess.run(['vppctl', 'show', 'interface'], 
                capture_output=True, timeout=5)
            vpp_ok = result.returncode == 0
        except:
            pass
        
        all_healthy = all([services['vpp'], services['flexiwan']]) and vpp_ok
        
        return {
            'status': 'healthy' if all_healthy else 'unhealthy',
            'pop': '${pop_name}',
            'server': ${server_index},
            'role': '${is_primary ? "primary" : "secondary"}',
            'nic_type': '${nic_type}',
            'nic_speed_gbps': ${nic_speed},
            'services': services,
            'vpp_interfaces': vpp_ok
        }
    
    def check_service(self, name):
        result = subprocess.run(['systemctl', 'is-active', name], 
            capture_output=True)
        return result.returncode == 0
    
    def send_metrics(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        # Prometheus format
        self.wfile.write(b'# HELP obmo_up OBMO health status\n')
        self.wfile.write(b'# TYPE obmo_up gauge\n')
        health = self.get_health()
        up = 1 if health['status'] == 'healthy' else 0
        self.wfile.write(f'obmo_up{{pop="{health["pop"]}"}} {up}\n'.encode())

if __name__ == '__main__':
    with socketserver.TCPServer(('', PORT), HealthHandler) as httpd:
        print(f"OBMO Health API running on port {PORT}")
        httpd.serve_forever()
HEALTHPY

chmod +x /opt/obmo-health.py

cat > /etc/systemd/system/obmo-health.service << 'EOF'
[Unit]
Description=OBMO Health Check API
After=network.target vpp.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/obmo-health.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl enable obmo-health

# ===========================================
# Start Services
# ===========================================

echo "Starting OBMO services..."

systemctl start vpp
sleep 5
systemctl start flexiwan
%{ if enable_bgp }
systemctl start bird
%{ endif }
systemctl start suricata
systemctl start obmo-health

# ===========================================
# Complete
# ===========================================

echo ""
echo "================================================================"
echo "  OBMO 100 Gbps Bootstrap Complete!"
echo "================================================================"
echo ""
echo "  Services Status:"
echo "    VPP:       $(systemctl is-active vpp)"
echo "    FlexiWAN:  $(systemctl is-active flexiwan)"
echo "    Suricata:  $(systemctl is-active suricata)"
echo "    BIRD:      $(systemctl is-active bird 2>/dev/null || echo 'N/A')"
echo ""
echo "  Health API:  http://localhost:8080/health"
echo "  Metrics:     http://localhost:8080/metrics"
echo ""
echo "  VPP Commands:"
echo "    vppctl show interface"
echo "    vppctl show hardware"
echo "    vppctl show dpdk version"
echo ""
echo "================================================================"
