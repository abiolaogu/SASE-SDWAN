#!/bin/bash
# deploy-edge.sh - Deploy flexiEdge with VPP integration
# OpenSASE SD-WAN Edge Deployment Script

set -euo pipefail

# ===========================================
# Configuration
# ===========================================

EDGE_NAME=${1:-"edge-01"}
FLEXIMANAGE_URL=${2:-"https://manage.opensase.io"}
ACTIVATION_TOKEN=${3:-""}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ===========================================
# Pre-flight Checks
# ===========================================

echo "==========================================="
echo "  OpenSASE Edge Deployment: ${EDGE_NAME}"
echo "==========================================="

if [ -z "$ACTIVATION_TOKEN" ]; then
    log_error "Activation token is required"
    echo "Usage: $0 <edge-name> <fleximanage-url> <activation-token>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root"
    exit 1
fi

# Check minimum requirements
log_info "Checking system requirements..."

TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
if [ "$TOTAL_MEM" -lt 8 ]; then
    log_warn "Recommended minimum 8GB RAM, found ${TOTAL_MEM}GB"
fi

CPU_CORES=$(nproc)
if [ "$CPU_CORES" -lt 4 ]; then
    log_warn "Recommended minimum 4 cores, found ${CPU_CORES}"
fi

# ===========================================
# 1. Install flexiEdge
# ===========================================

log_info "Installing flexiEdge..."

# Add flexiWAN repository
if [ ! -f /etc/apt/sources.list.d/flexiwan.list ]; then
    curl -sL https://deb.flexiwan.com/setup | bash
fi

apt-get update
apt-get install -y flexiwan-router

# ===========================================
# 2. Install VPP
# ===========================================

log_info "Installing VPP with DPDK..."

# Add FD.io repository
if [ ! -f /etc/apt/sources.list.d/fdio_release.list ]; then
    curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
fi

apt-get update
apt-get install -y \
    vpp \
    vpp-plugin-core \
    vpp-plugin-dpdk \
    vpp-plugin-wireguard \
    vpp-plugin-nat \
    vpp-plugin-acl

# ===========================================
# 3. Configure Hugepages
# ===========================================

log_info "Configuring hugepages..."

# Set hugepages (2GB for VPP)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Make persistent
if ! grep -q "hugepages" /etc/sysctl.conf; then
    cat >> /etc/sysctl.conf << 'EOF'
# VPP Hugepages
vm.nr_hugepages = 1024
vm.hugetlb_shm_group = 0
EOF
fi

# Mount hugetlbfs
if ! mount | grep -q hugetlbfs; then
    mkdir -p /dev/hugepages
    mount -t hugetlbfs nodev /dev/hugepages
    echo "hugetlbfs /dev/hugepages hugetlbfs defaults 0 0" >> /etc/fstab
fi

# ===========================================
# 4. Configure VPP
# ===========================================

log_info "Configuring VPP..."

cat > /etc/vpp/startup.conf << 'EOF'
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    log /var/log/vpp/vpp.log
    full-coredump
    gid vpp
}

api-trace {
    on
}

api-segment {
    gid vpp
}

socksvr {
    default
}

cpu {
    main-core 0
    corelist-workers 1-3
    scheduler-policy fifo
    scheduler-priority 50
}

dpdk {
    dev default {
        num-rx-queues 2
        num-tx-queues 2
    }
    # NICs will be bound by flexiEdge configuration
    uio-driver vfio-pci
    
    # Socket memory per NUMA node
    socket-mem 1024
    
    # Number of memory channels
    num-mbufs 131072
}

plugins {
    plugin default { enable }
    plugin dpdk_plugin.so { enable }
    plugin wireguard_plugin.so { enable }
    plugin nat_plugin.so { enable }
    plugin acl_plugin.so { enable }
    plugin ping_plugin.so { enable }
}

buffers {
    buffers-per-numa 128000
    default data-size 2048
}

statseg {
    socket-name /var/run/vpp/stats.sock
    size 128M
    per-node-counters on
}
EOF

# ===========================================
# 5. Configure flexiEdge to use VPP
# ===========================================

log_info "Configuring flexiEdge with VPP data plane..."

mkdir -p /etc/flexiwan

cat > /etc/flexiwan/agent.conf << EOF
{
    "deviceName": "${EDGE_NAME}",
    "dataPlane": "vpp",
    "vppSocketPath": "/run/vpp/cli.sock",
    "vppApiSocket": "/run/vpp/api.sock",
    "managementUrl": "${FLEXIMANAGE_URL}",
    "token": "${ACTIVATION_TOKEN}",
    "logLevel": "info",
    "telemetryInterval": 30,
    "healthCheckInterval": 10,
    "tunnelKeepalive": 25,
    "features": {
        "sdwan": true,
        "firewall": true,
        "nat": true,
        "qos": true,
        "ipsec": false,
        "wireguard": true
    }
}
EOF

# ===========================================
# 6. Create OpenSASE Edge Integration Service
# ===========================================

log_info "Creating OpenSASE edge integration service..."

mkdir -p /opt/opensase/bin
mkdir -p /var/log/opensase

# Download edge integration binary (or build from source)
if [ -f /opt/opensase/bin/edge-integration ]; then
    log_info "Edge integration binary already exists"
else
    log_warn "Edge integration binary not found, will be built from source"
    # In production: download pre-built binary
    # curl -sL https://releases.opensase.io/edge-integration -o /opt/opensase/bin/edge-integration
fi

cat > /etc/systemd/system/opensase-edge.service << 'EOF'
[Unit]
Description=OpenSASE Edge Integration Service
Documentation=https://docs.opensase.io/edge
After=network-online.target vpp.service flexiwan.service
Wants=network-online.target
Requires=vpp.service

[Service]
Type=simple
User=root
ExecStartPre=/bin/sleep 5
ExecStart=/opt/opensase/bin/edge-integration \
    --config /etc/flexiwan/agent.conf \
    --vpp-socket /run/vpp/cli.sock \
    --log-level info
Restart=always
RestartSec=5
StandardOutput=append:/var/log/opensase/edge.log
StandardError=append:/var/log/opensase/edge-error.log

# Security
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

# ===========================================
# 7. Create VPP-flexiEdge Bridge Service
# ===========================================

cat > /etc/systemd/system/vpp-bridge.service << 'EOF'
[Unit]
Description=VPP to flexiEdge Bridge
After=vpp.service
Requires=vpp.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/opensase/bin/vpp-bridge-init
ExecStop=/opt/opensase/bin/vpp-bridge-cleanup

[Install]
WantedBy=multi-user.target
EOF

# Create bridge init script
cat > /opt/opensase/bin/vpp-bridge-init << 'SCRIPT'
#!/bin/bash
# Initialize VPP-flexiEdge bridge

# Wait for VPP to be ready
for i in {1..30}; do
    if vppctl show version >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Create loopback for management
vppctl create loopback interface
vppctl set interface state loop0 up
vppctl set interface ip address loop0 10.255.255.1/32

# Enable NAT if needed
vppctl nat44 plugin enable sessions 10000

echo "VPP bridge initialized"
SCRIPT

chmod +x /opt/opensase/bin/vpp-bridge-init

# ===========================================
# 8. Reload systemd and enable services
# ===========================================

log_info "Enabling and starting services..."

systemctl daemon-reload

# Enable services
systemctl enable vpp
systemctl enable flexiwan
systemctl enable opensase-edge
systemctl enable vpp-bridge

# Start VPP first
log_info "Starting VPP..."
systemctl start vpp
sleep 3

# Check VPP is running
if ! vppctl show version >/dev/null 2>&1; then
    log_error "VPP failed to start"
    journalctl -u vpp -n 50
    exit 1
fi

# Start VPP bridge
log_info "Initializing VPP bridge..."
systemctl start vpp-bridge

# Start flexiWAN
log_info "Starting flexiEdge agent..."
systemctl start flexiwan
sleep 5

# Start OpenSASE integration (if binary exists)
if [ -f /opt/opensase/bin/edge-integration ]; then
    log_info "Starting OpenSASE edge integration..."
    systemctl start opensase-edge
fi

# ===========================================
# 9. Verification
# ===========================================

log_info "Verifying deployment..."

echo ""
echo "==========================================="
echo "  Deployment Summary"
echo "==========================================="

# VPP Status
echo -n "VPP: "
if systemctl is-active --quiet vpp; then
    echo -e "${GREEN}Running${NC}"
    vppctl show version | head -1
else
    echo -e "${RED}Not Running${NC}"
fi

# flexiWAN Status
echo -n "flexiEdge: "
if systemctl is-active --quiet flexiwan; then
    echo -e "${GREEN}Running${NC}"
else
    echo -e "${RED}Not Running${NC}"
fi

# Show VPP interfaces
echo ""
echo "VPP Interfaces:"
vppctl show interface

echo ""
echo "==========================================="
echo "  Edge deployment complete: ${EDGE_NAME}"
echo "==========================================="
echo ""
echo "Management URL: ${FLEXIMANAGE_URL}"
echo "Device should appear in flexiManage within 60 seconds"
echo ""
echo "Useful commands:"
echo "  vppctl show interface       - Show VPP interfaces"
echo "  vppctl show wireguard       - Show WireGuard tunnels"
echo "  vppctl show ip fib          - Show routing table"
echo "  journalctl -u flexiwan -f   - Follow flexiEdge logs"
echo ""
