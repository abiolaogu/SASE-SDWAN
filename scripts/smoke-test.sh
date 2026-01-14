#!/bin/bash
# OpenSASE-Lab Smoke Tests
# Validates all core functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
SKIPPED=0

print_header() {
    echo ""
    echo "========================================"
    echo "  OpenSASE-Lab Smoke Tests"
    echo "========================================"
    echo ""
}

test_result() {
    local name="$1"
    local status="$2"
    local message="$3"
    
    if [ "$status" = "pass" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $name"
        ((PASSED++))
    elif [ "$status" = "fail" ]; then
        echo -e "${RED}✗ FAIL${NC}: $name"
        echo -e "        ${message}"
        ((FAILED++))
    else
        echo -e "${YELLOW}○ SKIP${NC}: $name - $message"
        ((SKIPPED++))
    fi
}

wait_for_service() {
    local service="$1"
    local url="$2"
    local max_attempts="${3:-30}"
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 2
        ((attempt++))
    done
    return 1
}

# T1: SD-WAN overlay ping
test_sdwan_overlay() {
    echo "[T1] Testing SD-WAN overlay connectivity..."
    
    if ! docker ps | grep -q "branch-a"; then
        test_result "SD-WAN Overlay Ping" "skip" "branch-a container not running"
        return
    fi
    
    if docker exec branch-a ping -c 3 -W 2 10.200.0.1 > /dev/null 2>&1; then
        test_result "SD-WAN Overlay Ping" "pass"
    else
        test_result "SD-WAN Overlay Ping" "fail" "Cannot ping PoP from branch-a"
    fi
}

# T2: ZTNA access to app1
test_ztna_app1() {
    echo "[T2] Testing ZTNA access to App1..."
    
    if ! docker ps | grep -q "ziti-router-a"; then
        test_result "ZTNA Access App1" "skip" "Ziti router not running"
        return
    fi
    
    # Check if app1 is accessible via Ziti
    if docker exec ziti-router-a curl -sf http://10.201.0.100 > /dev/null 2>&1; then
        test_result "ZTNA Access App1" "pass"
    else
        test_result "ZTNA Access App1" "fail" "Cannot access app1 via ZTNA"
    fi
}

# T3: ZTNA access to app2
test_ztna_app2() {
    echo "[T3] Testing ZTNA access to App2..."
    
    if ! docker ps | grep -q "ziti-router-b"; then
        test_result "ZTNA Access App2" "skip" "Ziti router not running"
        return
    fi
    
    # Check if app2 is accessible via Ziti
    if docker exec ziti-router-b curl -sf http://10.202.0.100/get > /dev/null 2>&1; then
        test_result "ZTNA Access App2" "pass"
    else
        test_result "ZTNA Access App2" "fail" "Cannot access app2 via ZTNA"
    fi
}

# T4: IPS enabled
test_ips_enabled() {
    echo "[T4] Testing Suricata IPS mode..."
    
    if ! docker ps | grep -q "security-pop"; then
        test_result "IPS Enabled" "skip" "security-pop container not running"
        return
    fi
    
    if docker exec security-pop suricatasc -c "iface-stat" 2>/dev/null | grep -q "iface"; then
        test_result "IPS Enabled" "pass"
    else
        test_result "IPS Enabled" "fail" "Suricata not in IPS mode"
    fi
}

# T5: IPS logging
test_ips_logging() {
    echo "[T5] Testing Suricata logging..."
    
    if ! docker ps | grep -q "security-pop"; then
        test_result "IPS Logging" "skip" "security-pop container not running"
        return
    fi
    
    # Trigger a test alert
    docker exec security-pop curl -sf "http://localhost/opensase-test" > /dev/null 2>&1 || true
    sleep 2
    
    if docker exec security-pop test -f /var/log/suricata/eve.json; then
        test_result "IPS Logging" "pass"
    else
        test_result "IPS Logging" "fail" "eve.json not found"
    fi
}

# T6: Wazuh receives logs
test_wazuh_agents() {
    echo "[T6] Testing Wazuh agent registration..."
    
    if ! docker ps | grep -q "wazuh-manager"; then
        test_result "Wazuh Agents" "skip" "wazuh-manager container not running"
        return
    fi
    
    agent_count=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "ID:" || echo "0")
    
    if [ "$agent_count" -gt 0 ]; then
        test_result "Wazuh Agents" "pass"
    else
        test_result "Wazuh Agents" "fail" "No agents registered (found: $agent_count)"
    fi
}

# T7: Wazuh sample alert
test_wazuh_alerts() {
    echo "[T7] Testing Wazuh alerts..."
    
    if ! docker ps | grep -q "wazuh-manager"; then
        test_result "Wazuh Alerts" "skip" "wazuh-manager container not running"
        return
    fi
    
    # Check if alerts exist in the indexer
    alert_count=$(curl -sf "http://localhost:9200/wazuh-alerts-*/_count" 2>/dev/null | jq -r '.count // 0' || echo "0")
    
    if [ "$alert_count" -gt 0 ]; then
        test_result "Wazuh Alerts" "pass"
    else
        test_result "Wazuh Alerts" "fail" "No alerts in indexer (found: $alert_count)"
    fi
}

# T8: Keycloak health
test_keycloak_health() {
    echo "[T8] Testing Keycloak health..."
    
    if ! docker ps | grep -q "keycloak"; then
        test_result "Keycloak Health" "skip" "keycloak container not running"
        return
    fi
    
    if curl -sf "http://localhost:8443/health/ready" > /dev/null 2>&1; then
        test_result "Keycloak Health" "pass"
    else
        test_result "Keycloak Health" "fail" "Keycloak not ready"
    fi
}

# T9: Portal health
test_portal_health() {
    echo "[T9] Testing Portal health..."
    
    if ! docker ps | grep -q "portal-backend"; then
        test_result "Portal Health" "skip" "portal-backend container not running"
        return
    fi
    
    if curl -sf "http://localhost:8000/api/health" > /dev/null 2>&1; then
        test_result "Portal Health" "pass"
    else
        test_result "Portal Health" "fail" "Portal backend not responding"
    fi
}

# Summary
print_summary() {
    echo ""
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    echo -e "  ${GREEN}Passed${NC}: $PASSED"
    echo -e "  ${RED}Failed${NC}: $FAILED"
    echo -e "  ${YELLOW}Skipped${NC}: $SKIPPED"
    echo "========================================"
    echo ""
    
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed. Check the output above for details.${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Main
print_header

echo "Checking if services are running..."
if ! docker compose ps > /dev/null 2>&1; then
    echo "Error: Docker Compose services not running. Run 'make up' first."
    exit 1
fi

echo "Running smoke tests..."
echo ""

test_sdwan_overlay
test_ztna_app1
test_ztna_app2
test_ips_enabled
test_ips_logging
test_wazuh_agents
test_wazuh_alerts
test_keycloak_health
test_portal_health

print_summary
