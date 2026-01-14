#!/bin/bash
# OpenSASE-Lab Configuration Generator
# Generates sample configuration files (no secrets)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "==================================="
echo "OpenSASE-Lab Configuration Generator"
echo "==================================="

# Create necessary directories
echo "[1/5] Creating directories..."
mkdir -p "$PROJECT_DIR/data"
mkdir -p "$PROJECT_DIR/volumes"
mkdir -p "$PROJECT_DIR/docker/flexiwan-edge/branch-a"
mkdir -p "$PROJECT_DIR/docker/flexiwan-edge/branch-b"
mkdir -p "$PROJECT_DIR/docker/flexiwan-edge/branch-c"
mkdir -p "$PROJECT_DIR/docker/openziti-controller"
mkdir -p "$PROJECT_DIR/docker/openziti-router/pop"
mkdir -p "$PROJECT_DIR/docker/openziti-router/branch-a"
mkdir -p "$PROJECT_DIR/docker/openziti-router/branch-b"

# Generate FlexiWAN edge configs
echo "[2/5] Generating FlexiWAN edge configurations..."

for branch in branch-a branch-b branch-c; do
    cat > "$PROJECT_DIR/docker/flexiwan-edge/$branch/device.conf" << EOF
# FlexiWAN Edge Configuration - $branch
# This is a template - actual tokens are provisioned by the controller

[device]
name = $branch
interfaces = eth0
management_interface = eth0

[controller]
host = flexiwan-controller
port = 4433
ssl_verify = false

[tunnel]
type = wireguard
mtu = 1420
keepalive = 25

[logging]
level = info
file = /var/log/flexiwan/$branch.log
EOF
done

# Generate OpenZiti controller config
echo "[3/5] Generating OpenZiti controller configuration..."

cat > "$PROJECT_DIR/docker/openziti-controller/controller.yaml" << 'EOF'
v: 3

db: /persistent/ctrl.db

identity:
  cert: /openziti/pki/ctrl.cert
  server_cert: /openziti/pki/ctrl.server.cert
  key: /openziti/pki/ctrl.key
  ca: /openziti/pki/ctrl.ca.cert

ctrl:
  listener: tls:0.0.0.0:6262

mgmt:
  listener: tls:0.0.0.0:10000

edge:
  enrollment:
    signingCert:
      cert: /openziti/pki/signing.cert
      key: /openziti/pki/signing.key
  api:
    listener: tls:0.0.0.0:1280
    address: ziti-controller:1280

web:
  - name: all-apis
    bindPoints:
      - interface: 0.0.0.0:1280
        address: ziti-controller:1280
    apis:
      - binding: edge-management
        options: {}
      - binding: edge-client
        options: {}
      - binding: fabric
        options: {}

healthChecks:
  boltCheck:
    interval: 30s
    timeout: 20s
    initialDelay: 30s
EOF

# Generate OpenZiti router configs
echo "[4/5] Generating OpenZiti router configurations..."

for router in pop branch-a branch-b; do
    router_dir="$PROJECT_DIR/docker/openziti-router"
    if [ "$router" = "pop" ]; then
        router_path="$router_dir/pop"
    else
        router_path="$router_dir/$router"
    fi
    
    cat > "$router_path/router.yaml" << EOF
v: 3

identity:
  cert: /openziti/pki/router-$router.cert
  server_cert: /openziti/pki/router-$router.server.cert
  key: /openziti/pki/router-$router.key
  ca: /openziti/pki/router-$router.ca.cert

ctrl:
  endpoint: tls:ziti-controller:6262

link:
  dialers:
    - binding: transport
  listeners:
    - binding: transport
      bind: tls:0.0.0.0:10080
      advertise: tls:ziti-router-$router:10080

listeners:
  - binding: edge
    address: tls:0.0.0.0:3022
    options:
      advertise: ziti-router-$router:3022
  - binding: tunnel
    options:
      mode: host
      
csr:
  country: US
  province: NC
  locality: Charlotte
  organization: OpenSASE Lab
  organizationalUnit: IT
  sans:
    dns:
      - localhost
      - ziti-router-$router
    ip:
      - 127.0.0.1
EOF
done

# Generate sample Wazuh agent config
echo "[5/5] Generating Wazuh agent configuration..."

cat > "$PROJECT_DIR/docker/wazuh/agent/ossec.conf" << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>wazuh-manager</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu20, ubuntu20.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <frequency>43200</frequency>
  </rootcheck>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin</directories>
  </syscheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>
</ossec_config>
EOF

echo ""
echo "Configuration generation complete!"
echo ""
echo "Generated files:"
echo "  - FlexiWAN edge configs (3 branches)"
echo "  - OpenZiti controller config"
echo "  - OpenZiti router configs (3 routers)"
echo "  - Wazuh agent config template"
echo ""
echo "Next steps:"
echo "  1. Run 'make up' to start the lab"
echo "  2. Access FlexiWAN at http://localhost:3000"
echo "  3. Register edges via the FlexiWAN UI"
echo ""
