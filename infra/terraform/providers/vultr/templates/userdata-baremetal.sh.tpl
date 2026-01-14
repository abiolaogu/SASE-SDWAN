#!/bin/bash
# Vultr Bare Metal PoP Bootstrap
# High-performance 100 Gbps edge node

set -euo pipefail

exec > >(tee /var/log/opensase-bootstrap.log) 2>&1

echo "============================================"
echo "  OpenSASE Vultr Bare Metal Bootstrap"
echo "  PoP: ${pop_name}"
echo "  Server: ${server_index}"
echo "============================================"

export DEBIAN_FRONTEND=noninteractive

apt-get update && apt-get upgrade -y

apt-get install -y \
    curl wget git jq htop iotop \
    net-tools tcpdump iperf3 \
    python3 python3-pip

# High-performance sysctl
cat >> /etc/sysctl.conf << 'EOF'
# 100 Gbps tuning
net.core.rmem_max = 536870912
net.core.wmem_max = 536870912
net.core.netdev_max_backlog = 500000
net.ipv4.tcp_rmem = 65536 134217728 536870912
net.ipv4.tcp_wmem = 65536 134217728 536870912
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
vm.nr_hugepages = 4096
EOF
sysctl -p

# 8GB hugepages
mkdir -p /dev/hugepages
mount -t hugetlbfs nodev /dev/hugepages

# Install VPP
curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
apt-get install -y vpp vpp-plugin-core vpp-plugin-dpdk vpp-plugin-wireguard vpp-plugin-nat vpp-plugin-acl

cat > /etc/vpp/startup.conf << 'EOF'
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    full-coredump
}
cpu {
    main-core 0
    corelist-workers 2-15
    scheduler-policy fifo
    scheduler-priority 80
}
dpdk {
    dev default {
        num-rx-queues 8
        num-tx-queues 8
    }
    uio-driver vfio-pci
    socket-mem 4096,4096
    num-mbufs 524288
}
buffers {
    buffers-per-numa 500000
}
EOF

systemctl enable vpp

# FlexiEdge
curl -sL https://deb.flexiwan.com/setup | bash
apt-get install -y flexiwan-router

mkdir -p /etc/flexiwan
cat > /etc/flexiwan/agent.conf << EOF
{
    "deviceName": "${pop_name}-bm-${server_index}",
    "dataPlane": "vpp",
    "vppSocketPath": "/run/vpp/cli.sock",
    "managementUrl": "${controller_url}",
    "token": "${activation_key}"
}
EOF

systemctl enable flexiwan

# Suricata
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update && apt-get install -y suricata
suricata-update
systemctl enable suricata

# Start
systemctl start vpp
sleep 5
systemctl start flexiwan
systemctl start suricata

echo "Bare metal bootstrap complete!"
