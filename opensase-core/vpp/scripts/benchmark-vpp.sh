#!/bin/bash
#
# OpenSASE VPP Engine - Performance Benchmark Script
#
# Tests VPP packet processing performance using built-in tools.
# Measures latency, throughput, and packet rate.
#
# Usage: sudo ./benchmark-vpp.sh [duration_seconds]

set -euo pipefail

DURATION=${1:-10}
VPP_SOCK="/run/vpp/cli.sock"

echo "=============================================="
echo "  OpenSASE VPP Performance Benchmark"
echo "  Duration: ${DURATION}s"
echo "=============================================="
echo ""

# Check VPP is running
if ! pgrep -x vpp > /dev/null; then
    echo "Error: VPP is not running"
    echo "Start with: sudo systemctl start opensase-vpp"
    exit 1
fi

# Helper function for VPP CLI
vppctl_cmd() {
    sudo vppctl -s "$VPP_SOCK" "$@" 2>/dev/null
}

# ===============================
# Collect System Info
# ===============================
echo "=== System Information ==="
echo "  Hostname: $(hostname)"
echo "  Kernel: $(uname -r)"
echo "  CPUs: $(nproc)"
echo "  Memory: $(free -h | awk '/^Mem:/{print $2}')"
echo ""

# ===============================
# Collect VPP Info
# ===============================
echo "=== VPP Information ==="
vppctl_cmd show version
echo ""

echo "=== Interface Status ==="
vppctl_cmd show interface
echo ""

echo "=== Workers ==="
vppctl_cmd show threads
echo ""

# ===============================
# Clear Statistics
# ===============================
echo "=== Clearing Statistics ==="
vppctl_cmd clear runtime
vppctl_cmd clear errors
echo "Statistics cleared."
echo ""

# ===============================
# Wait for Traffic
# ===============================
echo "=== Collecting Metrics for ${DURATION}s ==="
sleep "$DURATION"

# ===============================
# Collect Results
# ===============================
echo ""
echo "=== VPP Runtime Statistics ==="
vppctl_cmd show runtime
echo ""

echo "=== OpenSASE Statistics ==="
vppctl_cmd show opensase stats
echo ""

echo "=== Error Counters ==="
vppctl_cmd show errors
echo ""

echo "=== Interface Statistics ==="
vppctl_cmd show interface
echo ""

# ===============================
# Node Performance
# ===============================
echo "=== Node Performance ==="
echo "(Sorted by calls)"
vppctl_cmd show runtime | head -50
echo ""

# ===============================
# Memory Usage
# ===============================
echo "=== Memory Usage ==="
vppctl_cmd show memory
echo ""

echo "=== Buffer Usage ==="
vppctl_cmd show buffers
echo ""

# ===============================
# Summary
# ===============================
echo "=============================================="
echo "  Benchmark Complete"
echo "=============================================="
echo ""
echo "Key metrics to check:"
echo "  - Vector rate (should be ~256 for optimal)"
echo "  - Clocks/packet (lower is better)"
echo "  - Interface rx/tx rates"
echo ""
echo "For detailed per-node latency:"
echo "  vppctl show runtime max"
echo ""
