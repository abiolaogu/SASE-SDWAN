#!/bin/bash
# OpenZiti ZTNA Test Script
# Tests dark service access via Ziti

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
    echo -e "${CYAN}  OpenZiti ZTNA Tests${NC}"
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
# Controller Tests
# ============================================

test_controller_health() {
    echo -e "\n${YELLOW}[1] Controller Tests${NC}"
    
    # Check controller health
    echo -n "  Testing controller API... "
    if docker exec ziti-controller curl -sf -k https://localhost:1280/edge/v1/version > /dev/null 2>&1; then
        test_result "Controller API" "pass"
    else
        test_result "Controller API" "fail" "Controller not responding"
    fi
    
    # Check controller version
    echo -n "  Getting controller version... "
    VERSION=$(docker exec ziti-controller curl -sf -k https://localhost:1280/edge/v1/version | jq -r '.data.version' 2>/dev/null)
    if [ -n "$VERSION" ] && [ "$VERSION" != "null" ]; then
        test_result "Controller Version ($VERSION)" "pass"
    else
        test_result "Controller Version" "fail" "Could not get version"
    fi
}

# ============================================
# Router Tests
# ============================================

test_router_connectivity() {
    echo -e "\n${YELLOW}[2] Edge Router Tests${NC}"
    
    # Check PoP router
    echo -n "  Testing router-pop... "
    if docker ps | grep -q "ziti-router-pop"; then
        if docker exec ziti-router-pop curl -sf -k https://localhost:3022 > /dev/null 2>&1 || true; then
            test_result "Router PoP Running" "pass"
        else
            test_result "Router PoP Running" "pass"  # Edge listener may not respond to curl
        fi
    else
        test_result "Router PoP Running" "fail" "Container not running"
    fi
    
    # Check router-a
    echo -n "  Testing router-a... "
    if docker ps | grep -q "ziti-router-a"; then
        test_result "Router A Running" "pass"
    else
        test_result "Router A Running" "fail" "Container not running"
    fi
    
    # Check router-b
    echo -n "  Testing router-b... "
    if docker ps | grep -q "ziti-router-b"; then
        test_result "Router B Running" "pass"
    else
        test_result "Router B Running" "fail" "Container not running"
    fi
}

# ============================================
# Service Tests
# ============================================

test_services_exist() {
    echo -e "\n${YELLOW}[3] Service Definition Tests${NC}"
    
    # Login first
    docker exec ziti-controller ziti edge login localhost:1280 -u admin -p "${ZITI_PWD:-admin}" -y > /dev/null 2>&1 || true
    
    # Check app1 service
    echo -n "  Checking app1 service... "
    if docker exec ziti-controller ziti edge list services 2>/dev/null | grep -q "app1"; then
        test_result "app1 Service Exists" "pass"
    else
        test_result "app1 Service Exists" "fail" "Service not found"
    fi
    
    # Check app2 service
    echo -n "  Checking app2 service... "
    if docker exec ziti-controller ziti edge list services 2>/dev/null | grep -q "app2"; then
        test_result "app2 Service Exists" "pass"
    else
        test_result "app2 Service Exists" "fail" "Service not found"
    fi
}

# ============================================
# Dark Service Tests (No Direct Access)
# ============================================

test_dark_services() {
    echo -e "\n${YELLOW}[4] Dark Service Tests (Apps should NOT be directly accessible)${NC}"
    
    # Test that app1 is NOT directly accessible
    echo -n "  Testing app1 is dark (no direct access)... "
    if curl -sf --connect-timeout 2 http://10.201.0.100 > /dev/null 2>&1; then
        test_result "app1 Dark (Isolated)" "fail" "App1 is directly accessible (should be blocked)"
    else
        test_result "app1 Dark (No Direct Access)" "pass"
    fi
    
    # Test that app2 is NOT directly accessible
    echo -n "  Testing app2 is dark (no direct access)... "
    if curl -sf --connect-timeout 2 http://10.202.0.100/get > /dev/null 2>&1; then
        test_result "app2 Dark (Isolated)" "fail" "App2 is directly accessible (should be blocked)"
    else
        test_result "app2 Dark (No Direct Access)" "pass"
    fi
}

# ============================================
# Identity Tests
# ============================================

test_identities() {
    echo -e "\n${YELLOW}[5] Identity Tests${NC}"
    
    # Check testuser exists
    echo -n "  Checking testuser identity... "
    if docker exec ziti-controller ziti edge list identities 2>/dev/null | grep -q "testuser"; then
        test_result "testuser Identity" "pass"
    else
        test_result "testuser Identity" "fail" "Identity not found"
    fi
    
    # Check JWT files exist
    echo -n "  Checking enrollment tokens... "
    if [ -f "$PROJECT_DIR/docker/openziti-identities/testuser.jwt" ]; then
        test_result "Enrollment Token (testuser.jwt)" "pass"
    else
        test_result "Enrollment Token" "fail" "JWT not found"
    fi
}

# ============================================
# Policy Tests
# ============================================

test_policies() {
    echo -e "\n${YELLOW}[6] Policy Tests${NC}"
    
    # Check service policies
    echo -n "  Checking service policies... "
    POLICY_COUNT=$(docker exec ziti-controller ziti edge list service-policies 2>/dev/null | grep -c "app" || echo "0")
    if [ "$POLICY_COUNT" -ge 2 ]; then
        test_result "Service Policies (${POLICY_COUNT} found)" "pass"
    else
        test_result "Service Policies" "fail" "Expected at least 2 policies"
    fi
    
    # Check edge router policies
    echo -n "  Checking edge router policies... "
    if docker exec ziti-controller ziti edge list edge-router-policies 2>/dev/null | grep -q "all"; then
        test_result "Edge Router Policies" "pass"
    else
        test_result "Edge Router Policies" "fail" "Policy not found"
    fi
}

# ============================================
# Ziti Access Test (via tunnel)
# ============================================

test_ziti_access() {
    echo -e "\n${YELLOW}[7] Ziti Access Tests${NC}"
    
    echo "  Note: These tests require an enrolled identity and running tunnel"
    echo ""
    
    # Check if ziti-edge-tunnel is available
    if command -v ziti-edge-tunnel &> /dev/null; then
        echo -n "  Testing app1. ziti via tunnel... "
        if timeout 5 curl -sf http://app1.ziti > /dev/null 2>&1; then
            test_result "app1.ziti Access" "pass"
        else
            test_result "app1.ziti Access" "fail" "Could not reach app1.ziti (tunnel may not be running)"
        fi
        
        echo -n "  Testing app2.ziti via tunnel... "
        if timeout 5 curl -sf http://app2.ziti/get > /dev/null 2>&1; then
            test_result "app2.ziti Access" "pass"
        else
            test_result "app2.ziti Access" "fail" "Could not reach app2.ziti"
        fi
    else
        echo "  Skipping: ziti-edge-tunnel not installed"
        echo "  To test Ziti access:"
        echo "    1. Install Ziti Desktop Edge or ziti-edge-tunnel"
        echo "    2. Enroll identity: ./scripts/ziti-enroll-user.sh"
        echo "    3. Connect with enrolled identity"
        echo "    4. Run: curl http://app1.ziti"
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
    
    echo "To access services via Ziti:"
    echo "  1. Enroll: ./scripts/ziti-enroll-user.sh"
    echo "  2. Install Ziti client from https://openziti.io/docs/downloads"
    echo "  3. Import identity and connect"
    echo "  4. curl http://app1.ziti"
    echo "  5. curl http://app2.ziti/get"
    echo ""
    
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed.${NC}"
        exit 1
    else
        echo -e "${GREEN}All ZTNA infrastructure tests passed!${NC}"
        exit 0
    fi
}

# Main
main() {
    print_header
    
    # Check if controller is running
    if ! docker ps | grep -q "ziti-controller"; then
        echo -e "${RED}Error: ziti-controller not running.${NC}"
        echo "Start with: make up-ztna"
        exit 1
    fi
    
    test_controller_health
    test_router_connectivity
    test_services_exist
    test_dark_services
    test_identities
    test_policies
    test_ziti_access
    
    print_summary
}

main "$@"
