#!/bin/bash
#
# OpenSASE VPP Engine - DPDK NIC Binding Script
#
# Binds network interfaces to DPDK-compatible drivers.
# Supports Mellanox ConnectX-6 and Intel E810 100GbE NICs.
#
# Usage: sudo ./bind_dpdk.sh <pci_address> [pci_address2] ...
#

set -e

echo "================================================"
echo "OpenSASE DPDK NIC Binding"
echo "================================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root"
   exit 1
fi

# DPDK directory
DPDK_DEVBIND="/usr/share/dpdk/usertools/dpdk-devbind.py"
ALT_DPDK_DEVBIND="/usr/bin/dpdk-devbind"

# Find dpdk-devbind
if [[ -f "$DPDK_DEVBIND" ]]; then
    DEVBIND=$DPDK_DEVBIND
elif [[ -f "$ALT_DPDK_DEVBIND" ]]; then
    DEVBIND=$ALT_DPDK_DEVBIND
else
    echo "Error: dpdk-devbind not found. Install dpdk package."
    exit 1
fi

# Show current status if no arguments
if [[ $# -eq 0 ]]; then
    echo ""
    echo "Current NIC status:"
    echo ""
    $DEVBIND --status-dev net
    echo ""
    echo "Usage: $0 <pci_address> [pci_address2] ..."
    echo "Example: $0 0000:81:00.0 0000:81:00.1"
    exit 0
fi

# Load required kernel modules
echo "Loading kernel modules..."

# For Intel NICs: use vfio-pci (preferred) or igb_uio
modprobe vfio-pci 2>/dev/null || true
modprobe uio 2>/dev/null || true
modprobe igb_uio 2>/dev/null || true

# Enable IOMMU for vfio-pci
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true

# Detect which driver to use
DPDK_DRIVER="vfio-pci"
if ! modprobe -n $DPDK_DRIVER 2>/dev/null; then
    DPDK_DRIVER="igb_uio"
    if ! modprobe -n $DPDK_DRIVER 2>/dev/null; then
        echo "Error: No suitable DPDK driver available (vfio-pci or igb_uio)"
        exit 1
    fi
fi
echo "Using DPDK driver: $DPDK_DRIVER"
modprobe $DPDK_DRIVER

echo ""
echo "Note: Mellanox ConnectX NICs use mlx5 driver and don't need binding."
echo "      Only Intel/Broadcom NICs need DPDK binding."
echo ""

# Process each PCI address
for PCI in "$@"; do
    echo "Processing $PCI..."
    
    # Get current driver
    CURRENT_DRIVER=$($DEVBIND --status | grep "$PCI" | awk '{print $NF}' | tr -d '()')
    
    # Check if Mellanox
    if lspci -s "$PCI" 2>/dev/null | grep -qi "mellanox\|mlx"; then
        echo "  Mellanox NIC detected - uses mlx5 driver (no binding needed)"
        echo "  VPP will use rdma plugin for this interface"
        continue
    fi
    
    # Unbind from current driver
    if [[ -n "$CURRENT_DRIVER" ]] && [[ "$CURRENT_DRIVER" != "$DPDK_DRIVER" ]]; then
        echo "  Unbinding from $CURRENT_DRIVER..."
        
        # Bring interface down first
        IFACE=$(ls /sys/bus/pci/devices/$PCI/net/ 2>/dev/null | head -1)
        if [[ -n "$IFACE" ]]; then
            ip link set $IFACE down 2>/dev/null || true
        fi
        
        $DEVBIND --unbind $PCI 2>/dev/null || true
    fi
    
    # Bind to DPDK driver
    echo "  Binding to $DPDK_DRIVER..."
    $DEVBIND --bind=$DPDK_DRIVER $PCI
    
    echo "  Done: $PCI bound to $DPDK_DRIVER"
done

echo ""
echo "Final NIC status:"
echo ""
$DEVBIND --status-dev net

echo ""
echo "================================================"
echo "DPDK binding complete."
echo ""
echo "To revert, run:"
echo "  dpdk-devbind --bind=<original_driver> <pci_address>"
echo ""
echo "Example for Intel E810:"
echo "  dpdk-devbind --bind=ice 0000:81:00.0"
echo ""
