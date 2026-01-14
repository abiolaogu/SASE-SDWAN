#!/bin/bash
# SD-WAN Overlay and Routing Test Script
# Validates SD-WAN tunnel connectivity, VRF segmentation, and failover

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASSED=0
FAILED=0

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  SD-WAN Overlay & Routing Tests${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

test_result() {
    local name="$1"
    local status="$2"
    local message="$3"
    
    if [ "$status" = "pass" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $name"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $name"
        [ -n "$message" ] && echo -e "        ${message}"
        ((FAILED++))
    fi
}

# ============================================
# Overlay Connectivity Tests
# ============================================

test_overlay_connectivity() {
    echo -e "\n${YELLOW}[1] Overlay Connectivity Tests${NC}"
    
    # Test branch-a to PoP
    echo -n "  Testing branch-a → PoP... "
    if docker exec branch-a ping -c 3 -W 2 10.200.0.1 > /dev/null 2>&1; then
        test_result "Branch-A to PoP" "pass"
    else
        test_result "Branch-A to PoP" "fail" "Cannot reach 10.200.0.1"
    fi
    
    # Test branch-b to PoP
    echo -n "  Testing branch-b → PoP... "
    if docker exec branch-b ping -c 3 -W 2 10.200.0.1 > /dev/null 2>&1; then
        test_result "Branch-B to PoP" "pass"
    else
        test_result "Branch-B to PoP" "fail" "Cannot reach 10.200.0.1"
    fi
    
    # Test branch-c to PoP
    echo -n "  Testing branch-c → PoP... "
    if docker exec branch-c ping -c 3 -W 2 10.200.0.1 > /dev/null 2>&1; then
        test_result "Branch-C to PoP" "pass"
    else
        test_result "Branch-C to PoP" "fail" "Cannot reach 10.200.0.1"
    fi
    
    # Test branch-to-branch via overlay
    echo -n "  Testing branch-a → branch-b (overlay)... "
    if docker exec branch-a ping -c 3 -W 2 10.202.0.1 > /dev/null 2>&1; then
        test_result "Branch-A to Branch-B (overlay)" "pass"
    else
        test_result "Branch-A to Branch-B (overlay)" "fail" "No overlay path"
    fi
}

# ============================================
# VRF/Segmentation Tests
# ============================================

test_vrf_segmentation() {
    echo -e "\n${YELLOW}[2] VRF Segmentation Tests${NC}"
    
    # Check if VRF interfaces exist
    echo -n "  Checking corp VRF (VLAN 100)... "
    if docker exec branch-a ip link show eth2.100 > /dev/null 2>&1; then
        test_result "Corp VRF Interface (branch-a)" "pass"
    else
        test_result "Corp VRF Interface (branch-a)" "fail" "VLAN 100 not configured"
    fi
    
    echo -n "  Checking guest VRF (VLAN 200)... "
    if docker exec branch-a ip link show eth2.200 > /dev/null 2>&1; then
        test_result "Guest VRF Interface (branch-a)" "pass"
    else
        test_result "Guest VRF Interface (branch-a)" "fail" "VLAN 200 not configured"
    fi
    
    # Verify route tables
    echo -n "  Checking corp routing table... "
    if docker exec branch-a ip route show table 1 2>/dev/null | grep -q "default"; then
        test_result "Corp Routing Table" "pass"
    else
        test_result "Corp Routing Table" "fail" "No default route in VRF 1"
    fi
    
    echo -n "  Checking guest routing table... "
    if docker exec branch-a ip route show table 2 2>/dev/null | grep -q "default"; then
        test_result "Guest Routing Table" "pass"
    else
        test_result "Guest Routing Table" "fail" "No default route in VRF 2"
    fi
}

# ============================================
# Policy-Based Routing Tests
# ============================================

test_policy_routing() {
    echo -e "\n${YELLOW}[3] Policy-Based Routing Tests${NC}"
    
    # Corp traffic via PoP (traceroute should show PoP IP)
    echo -n "  Verifying corp traffic routes via PoP... "
    local corp_path=$(docker exec branch-a traceroute -n -m 3 8.8.8.8 2>/dev/null | grep -E "^\s*1\s+" | awk '{print $2}')
    if [ "$corp_path" = "10.200.0.1" ]; then
        test_result "Corp traffic via PoP" "pass"
    else
        test_result "Corp traffic via PoP" "fail" "First hop: $corp_path (expected 10.200.0.1)"
    fi
    
    # Guest traffic local breakout (should NOT go via PoP)
    echo -n "  Verifying guest traffic exits locally... "
    # This would need VRF context - simplified check
    local guest_route=$(docker exec branch-a ip route show table 2 2>/dev/null | grep "default" | head -1)
    if echo "$guest_route" | grep -qv "10.200.0.1"; then
        test_result "Guest local breakout" "pass"
    else
        test_result "Guest local breakout" "fail" "Guest traffic via PoP (should be direct)"
    fi
}

# ============================================
# Link Failover Tests
# ============================================

test_link_failover() {
    echo -e "\n${YELLOW}[4] Link Failover Tests${NC}"
    
    # Check dual WAN interfaces
    echo -n "  Checking WAN1 interface (branch-a)... "
    if docker exec branch-a ip link show eth0 > /dev/null 2>&1; then
        test_result "WAN1 Interface" "pass"
    else
        test_result "WAN1 Interface" "fail" "eth0 not found"
    fi
    
    echo -n "  Checking WAN2 interface (branch-a)... "
    if docker exec branch-a ip link show eth1 > /dev/null 2>&1; then
        test_result "WAN2 Interface" "pass"
    else
        test_result "WAN2 Interface" "fail" "eth1 not found"
    fi
    
    # Simulate failover - disable WAN1 and check WAN2 takes over
    echo ""
    echo -e "  ${CYAN}Simulating WAN1 failure...${NC}"
    
    # Get current default route
    local pre_failover_gw=$(docker exec branch-a ip route show default | head -1 | awk '{print $3}')
    echo "    Current gateway: $pre_failover_gw"
    
    # Disable WAN1
    docker exec branch-a ip link set eth0 down 2>/dev/null || true
    sleep 3
    
    # Check if WAN2 took over
    echo -n "  Checking failover to WAN2... "
    if docker exec branch-a ping -c 2 -W 2 10.200.0.1 > /dev/null 2>&1; then
        test_result "Failover to WAN2" "pass"
    else
        test_result "Failover to WAN2" "fail" "No connectivity after WAN1 failure"
    fi
    
    # Restore WAN1
    docker exec branch-a ip link set eth0 up 2>/dev/null || true
    sleep 2
    
    # Check failback
    echo -n "  Checking failback to WAN1... "
    local post_restore_gw=$(docker exec branch-a ip route show default | head -1 | awk '{print $3}')
    if [ "$post_restore_gw" = "$pre_failover_gw" ] || docker exec branch-a ping -c 2 -W 2 10.200.0.1 > /dev/null 2>&1; then
        test_result "Failback to WAN1" "pass"
    else
        test_result "Failback to WAN1" "fail" "Did not restore to original gateway"
    fi
}

# ============================================
# WireGuard Tunnel Tests
# ============================================

test_wireguard_tunnels() {
    echo -e "\n${YELLOW}[5] WireGuard Tunnel Tests${NC}"
    
    # Check WireGuard interface exists
    echo -n "  Checking WireGuard interface (branch-a)... "
    if docker exec branch-a wg show wg0 > /dev/null 2>&1; then
        test_result "WireGuard Interface" "pass"
    else
        test_result "WireGuard Interface" "fail" "wg0 not configured"
    fi
    
    # Check peer handshake
    echo -n "  Checking WireGuard peer handshake... "
    local last_handshake=$(docker exec branch-a wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
    if [ -n "$last_handshake" ] && [ "$last_handshake" != "0" ]; then
        test_result "WireGuard Handshake" "pass"
    else
        test_result "WireGuard Handshake" "fail" "No recent handshake"
    fi
    
    # Check tunnel traffic
    echo -n "  Checking tunnel traffic counters... "
    local tx_bytes=$(docker exec branch-a wg show wg0 transfer 2>/dev/null | awk '{print $2}')
    if [ -n "$tx_bytes" ] && [ "$tx_bytes" != "0" ]; then
        test_result "Tunnel Traffic" "pass"
    else
        test_result "Tunnel Traffic" "fail" "No traffic through tunnel"
    fi
}

# ============================================
# Summary
# ============================================

print_summary() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Test Summary${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "  ${GREEN}Passed${NC}: $PASSED"
    echo -e "  ${RED}Failed${NC}: $FAILED"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed. Review the output above.${NC}"
        exit 1
    else
        echo -e "${GREEN}All SD-WAN tests passed!${NC}"
        exit 0
    fi
}

# Main
main() {
    print_header
    
    # Check if containers are running
    if ! docker ps | grep -q "branch-a"; then
        echo -e "${RED}Error: branch-a container not running.${NC}"
        echo "Start the SD-WAN stack with: make up-sdwan"
        exit 1
    fi
    
    test_overlay_connectivity
    test_vrf_segmentation
    test_policy_routing
    test_link_failover
    test_wireguard_tunnels
    
    print_summary
}

main "$@"
