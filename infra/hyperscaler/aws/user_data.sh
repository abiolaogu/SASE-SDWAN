#!/bin/bash
# ============================================================
# OpenSASE MVP Node Initialization
# ⚠️ SOFTWARE DATAPLANE MODE - NOT FOR PRODUCTION SCALE
# ============================================================

set -euo pipefail

echo "============================================================"
echo "⚠️  MVP/STARTUP DEPLOYMENT - Software Dataplane Mode  ⚠️"
echo "============================================================"

# Log everything
exec > >(tee /var/log/opensase-init.log) 2>&1

export DEBIAN_FRONTEND=noninteractive

# System updates
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y \
  curl \
  wget \
  git \
  jq \
  htop \
  iotop \
  net-tools \
  tcpdump \
  wireguard \
  wireguard-tools \
  docker.io \
  docker-compose \
  nginx \
  certbot \
  python3-certbot-nginx \
  prometheus-node-exporter \
  suricata \
  unbound

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Configure system for networking
cat >> /etc/sysctl.conf <<EOF
# OpenSASE Network Optimization (MVP/Software Mode)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_max_syn_backlog = 30000
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Connection tracking for NAT
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
EOF

sysctl -p

# Create OpenSASE directories
mkdir -p /opt/opensase/{config,data,logs,certs}
mkdir -p /var/log/opensase

# Get instance metadata
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region || echo "unknown")

# Create node configuration
cat > /opt/opensase/config/node.yaml <<EOF
# OpenSASE MVP Node Configuration
# ⚠️ This is a software-mode deployment for MVP/demo purposes

node:
  id: ${INSTANCE_ID}
  region: ${REGION}
  environment: mvp
  
dataplane:
  # MVP uses software dataplane (no DPDK/VPP)
  mode: software
  wireguard:
    listen_port: 51820
    health_port: 51821
  
proxy:
  mode: envoy
  listen_port: 443
  
dns:
  mode: unbound
  listen_port: 53
  upstream:
    - 1.1.1.1
    - 8.8.8.8
  filtering:
    enabled: true
    
security:
  ips:
    mode: suricata
    ruleset: et/open
    
metrics:
  prometheus:
    enabled: true
    port: 9090
    
logging:
  level: info
  output: /var/log/opensase/node.log
EOF

# Setup WireGuard
wg genkey | tee /opt/opensase/config/wg_private.key | wg pubkey > /opt/opensase/config/wg_public.key
chmod 600 /opt/opensase/config/wg_private.key

WG_PRIVATE_KEY=$(cat /opt/opensase/config/wg_private.key)
WG_IP="10.200.0.$((RANDOM % 253 + 2))"

# Configure WireGuard interface
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
ListenPort = 51820
Address = ${WG_IP}/24

# Peers will be dynamically added by control plane
EOF

# Start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Configure Suricata for MVP
suricata-update

# Start Suricata
systemctl enable suricata
systemctl start suricata

# Configure Unbound DNS
cat > /etc/unbound/unbound.conf.d/opensase.conf <<EOF
server:
    interface: 0.0.0.0
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    
    # Forwarding
    forward-zone:
        name: "."
        forward-addr: 1.1.1.1
        forward-addr: 8.8.8.8
EOF

systemctl restart unbound

# Health check endpoint
cat > /opt/opensase/health.sh <<'EOF'
#!/bin/bash
# Simple health check for load balancer
if systemctl is-active --quiet wg-quick@wg0; then
    echo "OK"
    exit 0
else
    echo "UNHEALTHY"
    exit 1
fi
EOF
chmod +x /opt/opensase/health.sh

# Create health check listener
cat > /etc/systemd/system/opensase-health.service <<EOF
[Unit]
Description=OpenSASE Health Check Listener
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK" | nc -l -p 51821 -q 1; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable opensase-health
systemctl start opensase-health

echo "============================================================"
echo "OpenSASE MVP Node Initialization Complete"
echo "Instance: ${INSTANCE_ID}"
echo "Region: ${REGION}"
echo "WireGuard IP: ${WG_IP}"
echo "============================================================"
