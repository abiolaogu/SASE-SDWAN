#!/bin/bash
# Equinix Metal PoP Bootstrap Script
# OpenSASE 100 Gbps Edge Node

set -euo pipefail

exec > >(tee /var/log/opensase-bootstrap.log) 2>&1

echo "============================================"
echo "  OpenSASE Equinix Metal PoP Bootstrap"
echo "  PoP: ${pop_name}"
echo "  Server: ${server_index}"
echo "  Role: ${is_primary ? "PRIMARY" : "SECONDARY"}"
echo "  BGP: ${enable_bgp ? "ENABLED" : "DISABLED"}"
echo "============================================"

# ===========================================
# System Configuration
# ===========================================

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get upgrade -y

# Install prerequisites
apt-get install -y \
    curl wget git jq htop iotop \
    net-tools tcpdump iperf3 \
    python3 python3-pip ansible \
    bird2 frr frr-pythontools

# ===========================================
# 100 Gbps Network Optimization
# ===========================================

cat >> /etc/sysctl.conf << 'EOF'
# 100 Gbps Network Tuning
net.core.rmem_max = 536870912
net.core.wmem_max = 536870912
net.core.rmem_default = 134217728
net.core.wmem_default = 134217728
net.core.netdev_max_backlog = 500000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 2000

net.ipv4.tcp_rmem = 65536 134217728 536870912
net.ipv4.tcp_wmem = 65536 134217728 536870912
net.ipv4.tcp_mem = 131072 262144 524288
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

vm.nr_hugepages = 4096
EOF

sysctl -p

# ===========================================
# Hugepages for VPP (8GB)
# ===========================================

mkdir -p /dev/hugepages
mount -t hugetlbfs nodev /dev/hugepages || true

# ===========================================
# Install VPP with DPDK
# ===========================================

curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
apt-get install -y \
    vpp vpp-plugin-core vpp-plugin-dpdk \
    vpp-plugin-wireguard vpp-plugin-nat vpp-plugin-acl \
    vpp-dev vpp-api-python

# Configure VPP for 100 Gbps
cat > /etc/vpp/startup.conf << 'EOF'
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    log /var/log/vpp/vpp.log
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
        num-rx-desc 4096
        num-tx-desc 4096
    }
    # Bind 100G NICs - detect automatically
    uio-driver vfio-pci
    socket-mem 4096,4096
    num-mbufs 524288
    no-multi-seg
}

buffers {
    buffers-per-numa 500000
    default data-size 2048
}

statseg {
    socket-name /var/run/vpp/stats.sock
    size 256M
    per-node-counters on
}
EOF

systemctl enable vpp

# ===========================================
# Install FlexiEdge
# ===========================================

curl -sL https://deb.flexiwan.com/setup | bash
apt-get install -y flexiwan-router

mkdir -p /etc/flexiwan
cat > /etc/flexiwan/agent.conf << EOF
{
    "deviceName": "${pop_name}-${server_index}",
    "dataPlane": "vpp",
    "vppSocketPath": "/run/vpp/cli.sock",
    "managementUrl": "${controller_url}",
    "token": "${activation_key}",
    "logLevel": "info",
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
cat > /etc/bird/bird.conf << EOF
router id from "lo";

protocol device {
    scan time 10;
}

protocol direct {
    ipv4;
    interface "lo";
}

protocol kernel {
    ipv4 {
        export all;
        import none;
    };
}

# BGP to Equinix Metal
protocol bgp equinix {
    local as ${bgp_asn};
    neighbor 169.254.255.1 as 65530;
    multihop 2;
    password "equinix_bgp_password";
    
    ipv4 {
        import none;
        export filter {
            # Announce anycast IPs
            if net ~ [ 0.0.0.0/0{24,32} ] then accept;
            reject;
        };
    };
}
EOF

systemctl enable bird
%{ endif }

# ===========================================
# Suricata IPS
# ===========================================

add-apt-repository -y ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata suricata-update

suricata-update
systemctl enable suricata

# ===========================================
# Start Services
# ===========================================

systemctl start vpp
sleep 5
systemctl start flexiwan
%{ if enable_bgp }
systemctl start bird
%{ endif }
systemctl start suricata

# ===========================================
# Health Check
# ===========================================

cat > /opt/opensase-health.py << 'HEALTHSCRIPT'
#!/usr/bin/env python3
import http.server
import json
import subprocess
import socketserver

PORT = 8080

class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            health = {
                'status': 'healthy',
                'pop': '${pop_name}',
                'server': ${server_index},
                'role': '${is_primary ? "primary" : "secondary"}',
                'vpp': self.check('vpp'),
                'flexiwan': self.check('flexiwan'),
                'suricata': self.check('suricata'),
                'bird': self.check('bird')
            }
            health['status'] = 'healthy' if all([
                health['vpp'], health['flexiwan'], health['suricata']
            ]) else 'unhealthy'
            
            self.send_response(200 if health['status'] == 'healthy' else 503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(health).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def check(self, service):
        return subprocess.run(['systemctl', 'is-active', service], 
            capture_output=True).returncode == 0

with socketserver.TCPServer(('', PORT), HealthHandler) as httpd:
    httpd.serve_forever()
HEALTHSCRIPT

chmod +x /opt/opensase-health.py

cat > /etc/systemd/system/opensase-health.service << 'EOF'
[Unit]
Description=OpenSASE Health API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/opensase-health.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable opensase-health
systemctl start opensase-health

echo "============================================"
echo "  Bootstrap Complete!"
echo "  Health: http://localhost:8080/health"
echo "============================================"
