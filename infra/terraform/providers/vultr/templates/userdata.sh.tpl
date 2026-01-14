#!/bin/bash
# Vultr PoP Bootstrap Script
# OpenSASE Cloud Edge Node

set -euo pipefail

exec > >(tee /var/log/opensase-bootstrap.log) 2>&1

echo "============================================"
echo "  OpenSASE Vultr Cloud PoP Bootstrap"
echo "  PoP: ${pop_name}"
echo "  Server: ${server_index}"
echo "  Role: ${is_primary ? "PRIMARY" : "SECONDARY"}"
echo "============================================"

export DEBIAN_FRONTEND=noninteractive

# System update
apt-get update && apt-get upgrade -y

# Install prerequisites
apt-get install -y \
    curl wget git jq htop iotop \
    net-tools tcpdump iperf3 \
    python3 python3-pip

# Configure sysctl
cat >> /etc/sysctl.conf << 'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
vm.nr_hugepages = 1024
EOF
sysctl -p

# Hugepages
mkdir -p /dev/hugepages
mount -t hugetlbfs nodev /dev/hugepages || true

# Install VPP
curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
apt-get install -y vpp vpp-plugin-core vpp-plugin-dpdk vpp-plugin-wireguard vpp-plugin-nat

cat > /etc/vpp/startup.conf << 'EOF'
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    log /var/log/vpp/vpp.log
}
cpu {
    main-core 0
    corelist-workers 1-3
}
dpdk {
    socket-mem 1024
}
plugins {
    plugin dpdk_plugin.so { enable }
    plugin wireguard_plugin.so { enable }
    plugin nat_plugin.so { enable }
}
EOF

systemctl enable vpp

# Install FlexiEdge
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
    "logLevel": "info"
}
EOF

systemctl enable flexiwan

# Install Suricata
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update && apt-get install -y suricata
suricata-update
systemctl enable suricata

# Start services
systemctl start vpp
sleep 3
systemctl start flexiwan
systemctl start suricata

# Health endpoint
cat > /opt/health.py << 'HEALTH'
#!/usr/bin/env python3
import http.server, json, subprocess, socketserver

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            h = {'status': 'healthy', 'pop': '${pop_name}', 'server': ${server_index}}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(h).encode())
        else:
            self.send_response(404)
            self.end_headers()

with socketserver.TCPServer(('', 8080), H) as s:
    s.serve_forever()
HEALTH

chmod +x /opt/health.py

cat > /etc/systemd/system/health.service << 'EOF'
[Unit]
Description=Health API
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/health.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl enable health && systemctl start health

echo "Bootstrap complete!"
