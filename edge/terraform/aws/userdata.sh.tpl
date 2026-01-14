#!/bin/bash
set -ex

# OpenSASE Edge - Auto-setup script

# Install dependencies
apt-get update
apt-get install -y wireguard docker.io jq curl

# Enable services
systemctl enable docker
systemctl start docker

# Create config directory
mkdir -p /etc/opensase

# Write configuration
cat > /etc/opensase/edge.json <<EOF
{
  "site_id": "$(uuidgen)",
  "site_name": "${site_name}",
  "tenant_id": "${tenant_id}",
  "controller_url": "${controller_url}",
  "activation_code": "${activation_code}",
  "interfaces": [
    {"name": "eth0", "role": "Wan", "dhcp": true, "priority": 100, "bandwidth_mbps": 100},
    {"name": "eth1", "role": "Lan", "dhcp": false, "static_ip": "10.0.0.1/24", "priority": 0, "bandwidth_mbps": 1000}
  ],
  "pop_connections": [
    {"pop_id": "pop-us-east", "endpoint": "pop1.opensase.io:51820", "public_key": "SERVER_KEY", "is_primary": true}
  ],
  "local_subnets": ["10.0.0.0/24"],
  "dns_servers": ["1.1.1.1", "8.8.8.8"],
  "security": {
    "firewall_enabled": true,
    "ips_enabled": true,
    "ips_mode": "prevent",
    "url_filter_enabled": true,
    "dns_security_enabled": true,
    "blocked_categories": ["malware", "phishing"]
  },
  "sdwan": {
    "path_selection": "LowestLatency",
    "probe_interval_ms": 1000,
    "failover_threshold_ms": 3000,
    "load_balance": true
  }
}
EOF

# Pull and run OpenSASE Edge
docker pull opensase/edge:latest
docker run -d \
  --name opensase-edge \
  --restart always \
  --cap-add NET_ADMIN \
  --network host \
  -v /etc/opensase:/etc/opensase:ro \
  opensase/edge:latest

echo "OpenSASE Edge installed successfully"
