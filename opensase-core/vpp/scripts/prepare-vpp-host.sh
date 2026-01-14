#!/bin/bash
#
# OpenSASE VPP Engine - Host Preparation Script
#
# Prepares a bare metal server for 100 Gbps VPP operation.
# Configures hugepages, CPU isolation, and DPDK drivers.
#
# Usage: sudo ./prepare-vpp-host.sh [--nic1 PCI] [--nic2 PCI]
#
# This script requires a reboot after running!

set -euo pipefail

# Default NIC PCI addresses (adjust for your hardware)
NIC1_PCI="${NIC1_PCI:-0000:41:00.0}"
NIC2_PCI="${NIC2_PCI:-0000:41:00.1}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --nic1)
            NIC1_PCI="$2"
            shift 2
            ;;
        --nic2)
            NIC2_PCI="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--nic1 PCI_ADDR] [--nic2 PCI_ADDR]"
            echo "Example: $0 --nic1 0000:41:00.0 --nic2 0000:41:00.1"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=============================================="
echo "  OpenSASE VPP Host Preparation"
echo "  Target: 100 Gbps with <5μs latency"
echo "=============================================="
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Detect hardware
echo "=== Detecting Hardware ==="
TOTAL_MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
TOTAL_CPUS=$(nproc)
NUMA_NODES=$(ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l)
[[ $NUMA_NODES -eq 0 ]] && NUMA_NODES=1

echo "  Total Memory: ${TOTAL_MEM_GB}GB"
echo "  Total CPUs: ${TOTAL_CPUS}"
echo "  NUMA Nodes: ${NUMA_NODES}"
echo "  NIC1 PCI: ${NIC1_PCI}"
echo "  NIC2 PCI: ${NIC2_PCI}"
echo ""

# Validate NICs exist
if ! lspci -s "$NIC1_PCI" &>/dev/null; then
    echo "Warning: NIC1 at $NIC1_PCI not found"
fi
if ! lspci -s "$NIC2_PCI" &>/dev/null; then
    echo "Warning: NIC2 at $NIC2_PCI not found"
fi

# Calculate hugepages (use 25% of RAM, minimum 32GB)
HUGEPAGES_GB=$((TOTAL_MEM_GB / 4))
[[ $HUGEPAGES_GB -lt 32 ]] && HUGEPAGES_GB=32
[[ $HUGEPAGES_GB -gt 128 ]] && HUGEPAGES_GB=128
HUGEPAGES_1G=$((HUGEPAGES_GB / NUMA_NODES))

echo "=== Configuring Hugepages ==="
echo "  Allocating ${HUGEPAGES_GB}GB total (${HUGEPAGES_1G}GB per NUMA)"

# Create sysctl configuration
cat > /etc/sysctl.d/80-vpp-hugepages.conf << 'EOF'
# OpenSASE VPP Engine - Hugepage Configuration
# Optimized for 100 Gbps packet processing

# 2MB hugepages as fallback (16384 = 32GB)
vm.nr_hugepages = 16384

# Shared memory limits for VPP
kernel.shmmax = 68719476736
kernel.shmall = 16777216

# Network buffer tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 31457280
net.core.wmem_default = 31457280

# Increase network backlog
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 5000

# TCP tuning (for non-VPP traffic)
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_max_syn_backlog = 65535

# Disable IPv6 (optional, reduces processing)
# net.ipv6.conf.all.disable_ipv6 = 1

# Reduce swap usage
vm.swappiness = 1
EOF

sysctl -p /etc/sysctl.d/80-vpp-hugepages.conf

echo ""
echo "=== Configuring GRUB for 1GB Hugepages ==="

# Calculate isolated CPUs (leave cores 0-3 for OS, rest for VPP)
if [[ $TOTAL_CPUS -gt 8 ]]; then
    ISOLATED_START=4
    ISOLATED_END=$((TOTAL_CPUS - 1))
else
    ISOLATED_START=2
    ISOLATED_END=$((TOTAL_CPUS - 1))
fi

GRUB_CMDLINE="default_hugepagesz=1G hugepagesz=1G hugepages=${HUGEPAGES_GB}"
GRUB_CMDLINE="${GRUB_CMDLINE} isolcpus=${ISOLATED_START}-${ISOLATED_END}"
GRUB_CMDLINE="${GRUB_CMDLINE} nohz_full=${ISOLATED_START}-${ISOLATED_END}"
GRUB_CMDLINE="${GRUB_CMDLINE} rcu_nocbs=${ISOLATED_START}-${ISOLATED_END}"
GRUB_CMDLINE="${GRUB_CMDLINE} intel_pstate=disable"
GRUB_CMDLINE="${GRUB_CMDLINE} processor.max_cstate=1"
GRUB_CMDLINE="${GRUB_CMDLINE} intel_idle.max_cstate=0"
GRUB_CMDLINE="${GRUB_CMDLINE} iommu=pt intel_iommu=on"

echo "Add the following to GRUB_CMDLINE_LINUX in /etc/default/grub:"
echo ""
echo "  $GRUB_CMDLINE"
echo ""

# Backup and update GRUB if requested
read -p "Update GRUB automatically? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cp /etc/default/grub /etc/default/grub.backup
    
    if grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
        # Append to existing
        sed -i "s/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"${GRUB_CMDLINE} /" /etc/default/grub
    else
        echo "GRUB_CMDLINE_LINUX=\"${GRUB_CMDLINE}\"" >> /etc/default/grub
    fi
    
    update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg
    echo "GRUB updated. Backup at /etc/default/grub.backup"
fi

echo ""
echo "=== Loading VFIO-PCI Driver ==="

# Load required modules
modprobe vfio-pci
modprobe vfio
modprobe vfio_iommu_type1

# Persist modules
cat > /etc/modules-load.d/vfio.conf << 'EOF'
vfio
vfio_iommu_type1
vfio-pci
EOF

echo ""
echo "=== Binding NICs to VFIO-PCI ==="

# Function to bind NIC
bind_nic_to_vfio() {
    local pci="$1"
    local name="$2"
    
    if ! lspci -s "$pci" &>/dev/null; then
        echo "  Skipping $name ($pci): not found"
        return
    fi
    
    # Get current driver
    local current_driver=""
    if [[ -L "/sys/bus/pci/devices/$pci/driver" ]]; then
        current_driver=$(basename $(readlink "/sys/bus/pci/devices/$pci/driver"))
    fi
    
    if [[ "$current_driver" == "vfio-pci" ]]; then
        echo "  $name ($pci): already bound to vfio-pci"
        return
    fi
    
    echo "  Binding $name ($pci) from '$current_driver' to vfio-pci..."
    
    # Unbind from current driver
    if [[ -n "$current_driver" ]]; then
        echo "$pci" > "/sys/bus/pci/devices/$pci/driver/unbind" 2>/dev/null || true
    fi
    
    # Set driver override
    echo "vfio-pci" > "/sys/bus/pci/devices/$pci/driver_override"
    
    # Bind to vfio-pci
    echo "$pci" > /sys/bus/pci/drivers/vfio-pci/bind
    
    echo "  $name ($pci): bound to vfio-pci ✓"
}

bind_nic_to_vfio "$NIC1_PCI" "NIC1"
bind_nic_to_vfio "$NIC2_PCI" "NIC2"

echo ""
echo "=== Disabling irqbalance ==="
systemctl stop irqbalance 2>/dev/null || true
systemctl disable irqbalance 2>/dev/null || true
echo "  irqbalance disabled ✓"

echo ""
echo "=== Setting CPU Governor to Performance ==="
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [[ -f "$gov" ]]; then
        echo "performance" > "$gov"
    fi
done
echo "  CPU governor set ✓"

# Create persistent governor setting
cat > /etc/systemd/system/cpu-performance.service << 'EOF'
[Unit]
Description=Set CPU governor to performance
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $gov 2>/dev/null || true; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cpu-performance.service

echo ""
echo "=== Installing VPP ==="

# Detect distro
if [[ -f /etc/debian_version ]]; then
    # Ubuntu/Debian
    echo "  Detected Debian/Ubuntu"
    
    # Add VPP repository
    curl -fsSL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
    
    apt-get update
    apt-get install -y vpp vpp-dev vpp-plugin-core vpp-plugin-dpdk
    
elif [[ -f /etc/redhat-release ]]; then
    # RHEL/CentOS/Rocky
    echo "  Detected RHEL/CentOS"
    
    cat > /etc/yum.repos.d/fdio-release.repo << 'EOF'
[fdio-release]
name=fd.io release
baseurl=https://packagecloud.io/fdio/release/el/8/$basearch
gpgcheck=0
enabled=1
EOF
    
    dnf install -y vpp vpp-devel vpp-plugins
fi

echo ""
echo "=== Creating VPP User ==="
if ! id vpp &>/dev/null; then
    useradd -r -s /sbin/nologin vpp
fi

# Allow vpp user to use hugepages
usermod -a -G hugetlbfs vpp 2>/dev/null || true

echo ""
echo "=============================================="
echo "  Host Preparation Complete!"
echo "=============================================="
echo ""
echo "  IMPORTANT: Reboot required for:"
echo "    - 1GB hugepage allocation"
echo "    - CPU isolation"
echo "    - IOMMU settings"
echo ""
echo "  After reboot:"
echo "    1. Verify hugepages: cat /proc/meminfo | grep Huge"
echo "    2. Verify NICs: dpdk-devbind --status"
echo "    3. Start VPP: sudo vpp -c /etc/vpp/startup.conf"
echo ""
echo "  Recommended: tail -f /var/log/vpp/vpp.log"
echo ""
