#!/bin/bash
#
# OpenSASE VPP Engine - Hugepages Setup Script
# 
# Configures hugepages for optimal VPP performance.
# Run this script before starting VPP.
#
# Usage: sudo ./setup_hugepages.sh [size_gb]
#

set -e

# Default: 32GB of hugepages (16GB per NUMA on 2-NUMA system)
HUGEPAGES_SIZE_GB=${1:-32}

# Calculate number of 1GB pages
NUM_1GB_PAGES=$HUGEPAGES_SIZE_GB

echo "================================================"
echo "OpenSASE VPP Hugepages Setup"
echo "================================================"
echo "Requested hugepages: ${HUGEPAGES_SIZE_GB}GB"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root"
   exit 1
fi

# Detect NUMA nodes
NUMA_NODES=$(ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l)
if [[ $NUMA_NODES -eq 0 ]]; then
    NUMA_NODES=1
fi
echo "Detected NUMA nodes: $NUMA_NODES"

# Calculate pages per NUMA node
PAGES_PER_NUMA=$((NUM_1GB_PAGES / NUMA_NODES))
echo "Pages per NUMA: $PAGES_PER_NUMA"
echo ""

# Check current hugepage allocation
echo "Current hugepages configuration:"
grep -i huge /proc/meminfo || true
echo ""

# Mount hugetlbfs if not mounted
HUGETLBFS_MOUNT="/dev/hugepages"
if ! mountpoint -q $HUGETLBFS_MOUNT 2>/dev/null; then
    echo "Mounting hugetlbfs at $HUGETLBFS_MOUNT..."
    mkdir -p $HUGETLBFS_MOUNT
    mount -t hugetlbfs nodev $HUGETLBFS_MOUNT -o pagesize=1G
fi

# Drop caches to free memory
echo "Dropping caches to free memory..."
sync
echo 3 > /proc/sys/vm/drop_caches

# Compact memory
echo "Compacting memory..."
echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true

# Configure 1GB hugepages per NUMA node
echo "Allocating hugepages..."

for node_path in /sys/devices/system/node/node*/hugepages/hugepages-1048576kB/nr_hugepages; do
    if [[ -f "$node_path" ]]; then
        node=$(echo "$node_path" | grep -oP 'node\d+')
        echo "  Setting $node: $PAGES_PER_NUMA x 1GB pages"
        echo $PAGES_PER_NUMA > "$node_path"
    fi
done

# If no per-NUMA control, use global
if [[ $NUMA_NODES -eq 1 ]]; then
    echo "  Setting global: $NUM_1GB_PAGES x 1GB pages"
    echo $NUM_1GB_PAGES > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || true
fi

# Also allocate some 2MB pages for smaller buffers
echo "Allocating 2MB hugepages..."
NUM_2MB_PAGES=1024
echo $NUM_2MB_PAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || true

# Verify allocation
echo ""
echo "Hugepages after allocation:"
grep -i huge /proc/meminfo
echo ""

# Set permissions for VPP
echo "Setting permissions..."
chmod 1777 $HUGETLBFS_MOUNT
chown root:vpp $HUGETLBFS_MOUNT 2>/dev/null || true

# Verify 1GB pages are properly allocated
ALLOCATED_1G=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || echo 0)
FREE_1G=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages 2>/dev/null || echo 0)

echo ""
echo "================================================"
echo "Summary:"
echo "  1GB pages allocated: $ALLOCATED_1G"
echo "  1GB pages free:      $FREE_1G"
echo "  Total memory:        ${ALLOCATED_1G}GB"
echo "================================================"

if [[ $ALLOCATED_1G -lt $NUM_1GB_PAGES ]]; then
    echo ""
    echo "WARNING: Could not allocate all requested hugepages."
    echo "This may be due to memory fragmentation."
    echo "Try rebooting with hugepages=<N> kernel parameter."
    echo ""
    echo "Add to /etc/default/grub:"
    echo "  GRUB_CMDLINE_LINUX=\"default_hugepagesz=1G hugepagesz=1G hugepages=$NUM_1GB_PAGES\""
    echo ""
fi

echo "Hugepage setup complete. Ready for VPP."
