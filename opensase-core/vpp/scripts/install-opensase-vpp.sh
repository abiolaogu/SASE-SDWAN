#!/bin/bash
#
# OpenSASE VPP Engine - Installation Script
#
# Complete installation of VPP and OpenSASE plugins
#
# Usage: sudo ./install-opensase-vpp.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPP_DIR="$(dirname "$SCRIPT_DIR")"

echo "=============================================="
echo "  OpenSASE VPP Engine Installation"
echo "=============================================="
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Detect distro
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="unknown"
fi

echo "Detected distribution: $DISTRO"
echo ""

# ===============================
# Step 1: Install VPP
# ===============================
echo "=== Step 1: Installing VPP ==="

case $DISTRO in
    ubuntu|debian)
        echo "  Adding FD.io repository..."
        curl -fsSL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
        
        echo "  Installing VPP packages..."
        apt-get update
        apt-get install -y \
            vpp \
            vpp-dev \
            vpp-plugin-core \
            vpp-plugin-dpdk \
            libvppinfra \
            libvppinfra-dev \
            vpp-api-python \
            python3-vpp-api
        ;;
        
    centos|rhel|rocky|almalinux)
        echo "  Adding FD.io repository..."
        cat > /etc/yum.repos.d/fdio-release.repo << 'EOF'
[fdio-release]
name=fd.io release
baseurl=https://packagecloud.io/fdio/release/el/$releasever/$basearch
gpgcheck=0
enabled=1
EOF
        
        echo "  Installing VPP packages..."
        dnf install -y \
            vpp \
            vpp-devel \
            vpp-plugins \
            vpp-api-python
        ;;
        
    fedora)
        echo "  Adding FD.io repository..."
        dnf install -y \
            vpp \
            vpp-devel \
            vpp-plugins
        ;;
        
    *)
        echo "Error: Unsupported distribution: $DISTRO"
        echo "Please install VPP manually from https://fd.io"
        exit 1
        ;;
esac

echo "  VPP installed ✓"
echo ""

# ===============================
# Step 2: Install Dependencies
# ===============================
echo "=== Step 2: Installing Dependencies ==="

case $DISTRO in
    ubuntu|debian)
        apt-get install -y \
            cmake \
            pkg-config \
            build-essential \
            libhyperscan-dev \
            libndpi-dev \
            libssl-dev
        ;;
        
    centos|rhel|rocky|almalinux|fedora)
        dnf install -y \
            cmake \
            pkgconfig \
            gcc \
            gcc-c++ \
            hyperscan-devel \
            openssl-devel
        # nDPI may need to be built from source on RHEL
        ;;
esac

echo "  Dependencies installed ✓"
echo ""

# ===============================
# Step 3: Build OpenSASE Plugins
# ===============================
echo "=== Step 3: Building OpenSASE Plugins ==="

cd "$VPP_DIR"

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DVPP_PLUGIN_DIR=/usr/lib/vpp_plugins

# Build
make -j$(nproc)

echo "  Plugins built ✓"
echo ""

# ===============================
# Step 4: Install Plugins
# ===============================
echo "=== Step 4: Installing OpenSASE Plugins ==="

make install

echo "  Plugins installed to /usr/lib/vpp_plugins ✓"
echo ""

# ===============================
# Step 5: Install Configuration
# ===============================
echo "=== Step 5: Installing Configuration ==="

# Backup existing config
if [[ -f /etc/vpp/startup.conf ]]; then
    cp /etc/vpp/startup.conf /etc/vpp/startup.conf.backup
    echo "  Backed up existing startup.conf"
fi

# Install OpenSASE config
cp "$VPP_DIR/config/startup-100g.conf" /etc/vpp/startup.conf
cp "$VPP_DIR/config/opensase.conf" /etc/vpp/opensase.conf

# Create log directory
mkdir -p /var/log/vpp
chown vpp:vpp /var/log/vpp

echo "  Configuration installed ✓"
echo ""

# ===============================
# Step 6: Install Systemd Service
# ===============================
echo "=== Step 6: Installing Systemd Service ==="

cat > /etc/systemd/system/opensase-vpp.service << 'EOF'
[Unit]
Description=OpenSASE VPP Engine
Documentation=https://github.com/opensase/opensase-core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/bin/mkdir -p /run/vpp
ExecStartPre=/usr/bin/chown vpp:vpp /run/vpp
ExecStart=/usr/bin/vpp -c /etc/vpp/startup.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Performance settings
LimitNOFILE=1048576
LimitMEMLOCK=infinity
LimitNPROC=infinity

# Security
NoNewPrivileges=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable opensase-vpp.service

echo "  Systemd service installed ✓"
echo ""

# ===============================
# Step 7: Verify Installation
# ===============================
echo "=== Step 7: Verifying Installation ==="

# Check VPP binary
if command -v vpp &> /dev/null; then
    VPP_VERSION=$(vpp --version 2>/dev/null || echo "unknown")
    echo "  VPP: $VPP_VERSION ✓"
else
    echo "  VPP: NOT FOUND ✗"
fi

# Check plugins
if [[ -f /usr/lib/vpp_plugins/opensase_plugin.so ]]; then
    echo "  opensase_plugin.so ✓"
else
    echo "  opensase_plugin.so ✗"
fi

if [[ -f /usr/lib/vpp_plugins/wireguard_tunnel_plugin.so ]]; then
    echo "  wireguard_tunnel_plugin.so ✓"
else
    echo "  wireguard_tunnel_plugin.so ✗"
fi

echo ""
echo "=============================================="
echo "  Installation Complete!"
echo "=============================================="
echo ""
echo "  Before starting VPP:"
echo "    1. Run: sudo ./prepare-vpp-host.sh"
echo "    2. Edit /etc/vpp/startup.conf (adjust PCI addresses)"
echo "    3. Edit /etc/vpp/opensase.conf (configure policies)"
echo "    4. Reboot for hugepages and CPU isolation"
echo ""
echo "  To start VPP:"
echo "    sudo systemctl start opensase-vpp"
echo ""
echo "  To access VPP CLI:"
echo "    sudo vppctl -s /run/vpp/cli.sock"
echo ""
