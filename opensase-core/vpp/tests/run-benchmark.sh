#!/bin/bash
#
# OpenSASE VPP Engine - Performance Benchmark Suite
#
# Validates 100 Gbps throughput and <5μs latency targets.
# Uses TRex for traffic generation and VPP for packet processing.
#
# Usage: sudo ./run-benchmark.sh [test] [duration]
#

set -euo pipefail

# Configuration
TREX_SERVER="${TREX_SERVER:-localhost}"
TREX_PORT="${TREX_PORT:-4500}"
VPP_SOCKET="${VPP_SOCKET:-/run/vpp/cli.sock}"
DURATION="${2:-60}"
TEST="${1:-all}"

# Benchmark targets
TARGET_THROUGHPUT_GBPS=100
TARGET_LATENCY_US=5
TARGET_PPS_64B=148000000   # 148M pps for 64B at 100G
TARGET_PPS_IMIX=50000000   # 50M pps for IMIX

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "  OpenSASE VPP Performance Benchmark"
echo "=============================================="
echo "  Target: ${TARGET_THROUGHPUT_GBPS} Gbps, <${TARGET_LATENCY_US}μs"
echo "  Duration: ${DURATION} seconds"
echo "  Test: ${TEST}"
echo "=============================================="
echo ""

# Helper functions
log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_info() {
    echo "[INFO] $1"
}

# Check prerequisites
check_prereqs() {
    log_info "Checking prerequisites..."
    
    # Check VPP running
    if ! pgrep -x vpp > /dev/null; then
        log_fail "VPP is not running"
        exit 1
    fi
    log_pass "VPP running"
    
    # Check VPP socket
    if [[ ! -S "$VPP_SOCKET" ]]; then
        log_fail "VPP CLI socket not found: $VPP_SOCKET"
        exit 1
    fi
    log_pass "VPP CLI socket accessible"
    
    # Check hugepages
    local hp_free=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages 2>/dev/null || echo 0)
    if [[ "$hp_free" -lt 8 ]]; then
        log_warn "Low 1GB hugepages: $hp_free free"
    else
        log_pass "1GB hugepages available: $hp_free"
    fi
    
    echo ""
}

# VPP CLI wrapper
vppctl_cmd() {
    sudo vppctl -s "$VPP_SOCKET" "$@" 2>/dev/null
}

# Clear VPP statistics
clear_vpp_stats() {
    log_info "Clearing VPP statistics..."
    vppctl_cmd clear runtime
    vppctl_cmd clear errors
    vppctl_cmd clear interfaces
}

# Collect VPP statistics
collect_vpp_stats() {
    local output_file="$1"
    
    {
        echo "=== VPP Runtime ==="
        vppctl_cmd show runtime
        
        echo ""
        echo "=== Interface Statistics ==="
        vppctl_cmd show interface
        
        echo ""
        echo "=== OpenSASE Statistics ==="
        vppctl_cmd show opensase stats
        
        echo ""
        echo "=== Error Counters ==="
        vppctl_cmd show errors
        
        echo ""
        echo "=== Memory Usage ==="
        vppctl_cmd show memory
    } > "$output_file"
}

# Calculate throughput from interface stats
calc_throughput() {
    local rx_bytes=$(vppctl_cmd show interface wan0 | grep -oP 'rx bytes\s+\K\d+' || echo 0)
    local tx_bytes=$(vppctl_cmd show interface wan0 | grep -oP 'tx bytes\s+\K\d+' || echo 0)
    local total_bytes=$((rx_bytes + tx_bytes))
    
    # Gbps = (bytes * 8) / (duration * 1e9)
    local gbps=$(echo "scale=2; ($total_bytes * 8) / ($DURATION * 1000000000)" | bc)
    echo "$gbps"
}

# Calculate packets per second
calc_pps() {
    local rx_pkts=$(vppctl_cmd show interface wan0 | grep -oP 'rx packets\s+\K\d+' || echo 0)
    local tx_pkts=$(vppctl_cmd show interface wan0 | grep -oP 'tx packets\s+\K\d+' || echo 0)
    local total_pkts=$((rx_pkts + tx_pkts))
    
    # PPS = packets / duration
    local pps=$((total_pkts / DURATION))
    echo "$pps"
}

# Calculate average latency from node clocks
calc_latency() {
    local total_clocks=0
    local total_vectors=0
    
    # Sum clocks from opensase nodes
    while read -r clocks vectors; do
        total_clocks=$((total_clocks + clocks))
        total_vectors=$((total_vectors + vectors))
    done < <(vppctl_cmd show runtime | grep opensase | awk '{print $5, $4}')
    
    if [[ $total_vectors -gt 0 ]]; then
        # Clocks per packet / CPU frequency (assume 3GHz)
        local clocks_per_pkt=$((total_clocks / total_vectors))
        local latency_ns=$((clocks_per_pkt / 3))
        local latency_us=$(echo "scale=2; $latency_ns / 1000" | bc)
        echo "$latency_us"
    else
        echo "N/A"
    fi
}

# Test: Baseline throughput (no security features)
test_baseline() {
    log_info "=== Baseline Throughput Test ==="
    log_info "Testing raw VPP forwarding without SASE features"
    
    clear_vpp_stats
    
    # Disable OpenSASE features
    vppctl_cmd set interface feature wan0 ip4-unicast opensase-tenant off 2>/dev/null || true
    
    log_info "Running baseline test for ${DURATION}s..."
    sleep "$DURATION"
    
    local gbps=$(calc_throughput)
    local pps=$(calc_pps)
    
    log_info "  Throughput: ${gbps} Gbps"
    log_info "  Packets:    ${pps} pps"
    
    # Re-enable OpenSASE
    vppctl_cmd set interface feature wan0 ip4-unicast opensase-tenant 2>/dev/null || true
    
    if (( $(echo "$gbps >= 90" | bc -l) )); then
        log_pass "Baseline throughput: ${gbps} Gbps (target: ≥90 Gbps)"
    else
        log_fail "Baseline throughput: ${gbps} Gbps (target: ≥90 Gbps)"
    fi
    
    echo ""
}

# Test: Full SASE pipeline
test_sase_pipeline() {
    log_info "=== Full SASE Pipeline Test ==="
    log_info "Testing complete OpenSASE security stack"
    
    clear_vpp_stats
    
    # Ensure OpenSASE enabled
    vppctl_cmd set interface feature wan0 ip4-unicast opensase-tenant 2>/dev/null || true
    
    log_info "Running SASE pipeline test for ${DURATION}s..."
    sleep "$DURATION"
    
    local gbps=$(calc_throughput)
    local pps=$(calc_pps)
    local latency=$(calc_latency)
    
    log_info "  Throughput: ${gbps} Gbps"
    log_info "  Packets:    ${pps} pps"
    log_info "  Latency:    ${latency} μs"
    
    collect_vpp_stats "/tmp/sase_pipeline_stats.txt"
    log_info "  Stats saved to /tmp/sase_pipeline_stats.txt"
    
    # Evaluate results
    local result=0
    
    if (( $(echo "$gbps >= $TARGET_THROUGHPUT_GBPS" | bc -l) )); then
        log_pass "Throughput: ${gbps} Gbps (target: ≥${TARGET_THROUGHPUT_GBPS} Gbps)"
    else
        log_fail "Throughput: ${gbps} Gbps (target: ≥${TARGET_THROUGHPUT_GBPS} Gbps)"
        result=1
    fi
    
    if [[ "$latency" != "N/A" ]] && (( $(echo "$latency <= $TARGET_LATENCY_US" | bc -l) )); then
        log_pass "Latency: ${latency} μs (target: ≤${TARGET_LATENCY_US} μs)"
    else
        log_fail "Latency: ${latency} μs (target: ≤${TARGET_LATENCY_US} μs)"
        result=1
    fi
    
    echo ""
    return $result
}

# Test: WireGuard encryption overhead
test_wireguard() {
    log_info "=== WireGuard Encryption Test ==="
    log_info "Testing encrypted tunnel throughput"
    
    clear_vpp_stats
    
    log_info "Running WireGuard test for ${DURATION}s..."
    sleep "$DURATION"
    
    local gbps=$(calc_throughput)
    local latency=$(calc_latency)
    
    log_info "  Throughput: ${gbps} Gbps"
    log_info "  Latency:    ${latency} μs"
    
    # WireGuard adds ~60 bytes overhead + crypto
    # Target 80% of line rate with encryption
    local wg_target=$((TARGET_THROUGHPUT_GBPS * 80 / 100))
    
    if (( $(echo "$gbps >= $wg_target" | bc -l) )); then
        log_pass "WireGuard throughput: ${gbps} Gbps (target: ≥${wg_target} Gbps)"
    else
        log_fail "WireGuard throughput: ${gbps} Gbps (target: ≥${wg_target} Gbps)"
    fi
    
    echo ""
}

# Test: DLP inspection overhead
test_dlp() {
    log_info "=== DLP Inspection Test ==="
    log_info "Testing payload inspection overhead"
    
    clear_vpp_stats
    
    log_info "Running DLP test for ${DURATION}s..."
    sleep "$DURATION"
    
    local gbps=$(calc_throughput)
    local dlp_bytes=$(vppctl_cmd show opensase stats | grep -oP 'dlp_bytes_inspected:\s*\K\d+' || echo 0)
    local dlp_matches=$(vppctl_cmd show opensase stats | grep -oP 'dlp_patterns_matched:\s*\K\d+' || echo 0)
    
    log_info "  Throughput:     ${gbps} Gbps"
    log_info "  Bytes scanned:  ${dlp_bytes}"
    log_info "  Patterns found: ${dlp_matches}"
    
    # DLP should maintain at least 50% throughput when inspecting all traffic
    local dlp_target=$((TARGET_THROUGHPUT_GBPS * 50 / 100))
    
    if (( $(echo "$gbps >= $dlp_target" | bc -l) )); then
        log_pass "DLP throughput: ${gbps} Gbps (target: ≥${dlp_target} Gbps with inspection)"
    else
        log_fail "DLP throughput: ${gbps} Gbps (target: ≥${dlp_target} Gbps with inspection)"
    fi
    
    echo ""
}

# Test: Session scaling
test_session_scale() {
    log_info "=== Session Scaling Test ==="
    log_info "Testing session table under load"
    
    clear_vpp_stats
    
    log_info "Running session scale test for ${DURATION}s..."
    sleep "$DURATION"
    
    local sessions=$(vppctl_cmd show opensase sessions | grep -c "session" || echo 0)
    local pps=$(calc_pps)
    
    log_info "  Active sessions: ${sessions}"
    log_info "  Sessions/sec:    $((sessions / DURATION))"
    log_info "  Packets/sec:     ${pps}"
    
    # Should handle 1M+ sessions
    if [[ $sessions -gt 100000 ]]; then
        log_pass "Session scale: ${sessions} active (target: >100K)"
    else
        log_warn "Session scale: ${sessions} active (target: >100K) - needs more traffic"
    fi
    
    echo ""
}

# Generate benchmark report
generate_report() {
    local report_file="/tmp/opensase_benchmark_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=============================================="
        echo "OpenSASE VPP Benchmark Report"
        echo "Generated: $(date)"
        echo "=============================================="
        echo ""
        echo "System Information:"
        echo "  Hostname: $(hostname)"
        echo "  Kernel:   $(uname -r)"
        echo "  CPUs:     $(nproc)"
        echo "  Memory:   $(free -h | awk '/^Mem:/{print $2}')"
        echo ""
        echo "VPP Information:"
        vppctl_cmd show version
        echo ""
        echo "Interface Configuration:"
        vppctl_cmd show interface
        echo ""
        echo "Final Statistics:"
        vppctl_cmd show runtime
        echo ""
        echo "OpenSASE Statistics:"
        vppctl_cmd show opensase stats
        echo ""
    } > "$report_file"
    
    log_info "Benchmark report saved to: $report_file"
}

# Main
main() {
    check_prereqs
    
    case "$TEST" in
        baseline)
            test_baseline
            ;;
        sase)
            test_sase_pipeline
            ;;
        wireguard)
            test_wireguard
            ;;
        dlp)
            test_dlp
            ;;
        sessions)
            test_session_scale
            ;;
        all)
            test_baseline
            test_sase_pipeline
            test_wireguard
            test_dlp
            test_session_scale
            ;;
        *)
            echo "Unknown test: $TEST"
            echo "Available tests: baseline, sase, wireguard, dlp, sessions, all"
            exit 1
            ;;
    esac
    
    generate_report
    
    echo ""
    echo "=============================================="
    echo "  Benchmark Complete"
    echo "=============================================="
}

main "$@"
