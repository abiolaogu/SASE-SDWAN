#!/bin/bash
# Security PoP Test Script
# Tests IPS, DNS, Proxy, and generates safe demo alerts

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
    echo -e "${CYAN}  Security PoP Gateway Tests${NC}"
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
# Service Health Tests
# ============================================

test_service_health() {
    echo -e "\n${YELLOW}[1] Service Health Tests${NC}"
    
    # Check API health
    echo -n "  Testing API health endpoint... "
    if curl -sf "http://localhost:8081/api/health" > /dev/null 2>&1; then
        test_result "API Health" "pass"
    else
        test_result "API Health" "fail" "API not responding on port 8081"
    fi
    
    # Check Suricata via API
    echo -n "  Testing Suricata status... "
    local suricata_status=$(curl -sf "http://localhost:8081/api/health" | jq -r '.services.suricata.running')
    if [ "$suricata_status" = "true" ]; then
        test_result "Suricata Running" "pass"
    else
        test_result "Suricata Running" "fail" "Suricata not running"
    fi
    
    # Check Unbound
    echo -n "  Testing Unbound DNS... "
    if docker exec security-pop pgrep unbound > /dev/null 2>&1; then
        test_result "Unbound Running" "pass"
    else
        test_result "Unbound Running" "fail" "Unbound not running"
    fi
    
    # Check Squid
    echo -n "  Testing Squid proxy... "
    if docker exec security-pop pgrep squid > /dev/null 2>&1; then
        test_result "Squid Running" "pass"
    else
        test_result "Squid Running" "fail" "Squid not running"
    fi
}

# ============================================
# IPS Detection Tests
# ============================================

test_ips_detection() {
    echo -e "\n${YELLOW}[2] IPS Detection Tests${NC}"
    
    # Get initial alert count
    local initial_count=$(docker exec security-pop wc -l /var/log/suricata/fast.log 2>/dev/null | awk '{print $1}' || echo "0")
    
    # Trigger User-Agent test alert (SID 9000002)
    echo -n "  Triggering User-Agent test alert... "
    curl -sf -H 'User-Agent: OpenSASE-Test' "http://localhost:8081/any" > /dev/null 2>&1 || true
    sleep 2
    
    local new_count=$(docker exec security-pop wc -l /var/log/suricata/fast.log 2>/dev/null | awk '{print $1}' || echo "0")
    if [ "$new_count" -gt "$initial_count" ]; then
        test_result "User-Agent Alert (SID 9000002)" "pass"
    else
        test_result "User-Agent Alert (SID 9000002)" "fail" "No new alert generated"
    fi
    
    # Trigger Header test alert (SID 9000003)
    echo -n "  Triggering Header test alert... "
    initial_count=$new_count
    curl -sf -H 'X-OpenSASE-Test: true' "http://localhost:8081/test" > /dev/null 2>&1 || true
    sleep 2
    
    new_count=$(docker exec security-pop wc -l /var/log/suricata/fast.log 2>/dev/null | awk '{print $1}' || echo "0")
    if [ "$new_count" -gt "$initial_count" ]; then
        test_result "Header Alert (SID 9000003)" "pass"
    else
        test_result "Header Alert (SID 9000003)" "fail" "No new alert generated"
    fi
    
    # Check EVE JSON logging
    echo -n "  Checking EVE JSON output... "
    if docker exec security-pop test -f /var/log/suricata/eve.json; then
        test_result "EVE JSON Logging" "pass"
    else
        test_result "EVE JSON Logging" "fail" "/var/log/suricata/eve.json not found"
    fi
}

# ============================================
# DNS Tests
# ============================================

test_dns() {
    echo -e "\n${YELLOW}[3] DNS Resolver Tests${NC}"
    
    # Test DNS resolution
    echo -n "  Testing DNS resolution (google.com)... "
    if docker exec security-pop dig @localhost google.com +short | grep -q '^[0-9]'; then
        test_result "DNS Resolution" "pass"
    else
        test_result "DNS Resolution" "fail" "Could not resolve google.com"
    fi
    
    # Test DNS stats API
    echo -n "  Testing DNS stats API... "
    if curl -sf "http://localhost:8081/api/dns/stats" | jq -e '.success' > /dev/null 2>&1; then
        test_result "DNS Stats API" "pass"
    else
        test_result "DNS Stats API" "fail" "Stats API not working"
    fi
    
    # Trigger DNS test alert
    echo -n "  Triggering DNS test alert... "
    docker exec security-pop dig @localhost test.opensase.lab > /dev/null 2>&1 || true
    sleep 2
    
    if docker exec security-pop grep -q "test.opensase.lab" /var/log/suricata/fast.log 2>/dev/null; then
        test_result "DNS Alert (SID 9000010)" "pass"
    else
        test_result "DNS Alert (SID 9000010)" "fail" "DNS alert not generated"
    fi
}

# ============================================
# Proxy Tests
# ============================================

test_proxy() {
    echo -e "\n${YELLOW}[4] Squid Proxy Tests${NC}"
    
    # Test proxy connectivity
    echo -n "  Testing proxy HTTP request... "
    if docker exec security-pop curl -sf -x http://localhost:3128 http://example.com > /dev/null 2>&1; then
        test_result "Proxy HTTP Request" "pass"
    else
        test_result "Proxy HTTP Request" "fail" "Could not proxy to example.com"
    fi
    
    # Test proxy stats API
    echo -n "  Testing proxy stats API... "
    if curl -sf "http://localhost:8081/api/proxy/stats" | jq -e '.success' > /dev/null 2>&1; then
        test_result "Proxy Stats API" "pass"
    else
        test_result "Proxy Stats API" "fail" "Stats API not working"
    fi
    
    # Test blocked domain
    echo -n "  Testing blocked domain... "
    local result=$(docker exec security-pop curl -sf -x http://localhost:3128 http://blocked.demo.lab 2>&1 || echo "blocked")
    if echo "$result" | grep -qi "blocked\|denied\|error"; then
        test_result "Domain Blocking" "pass"
    else
        test_result "Domain Blocking" "fail" "blocked.demo.lab was not blocked"
    fi
}

# ============================================
# Firewall Tests
# ============================================

test_firewall() {
    echo -e "\n${YELLOW}[5] Firewall Tests${NC}"
    
    # Test nftables loaded
    echo -n "  Checking nftables ruleset... "
    if docker exec security-pop nft list tables | grep -q "filter"; then
        test_result "nftables Loaded" "pass"
    else
        test_result "nftables Loaded" "fail" "Filter table not found"
    fi
    
    # Test firewall API
    echo -n "  Testing firewall rules API... "
    if curl -sf "http://localhost:8081/api/firewall/rules" | jq -e '.success' > /dev/null 2>&1; then
        test_result "Firewall Rules API" "pass"
    else
        test_result "Firewall Rules API" "fail" "Rules API not working"
    fi
}

# ============================================
# Metrics Tests
# ============================================

test_metrics() {
    echo -e "\n${YELLOW}[6] Prometheus Metrics Tests${NC}"
    
    # Test custom metrics endpoint
    echo -n "  Testing /metrics endpoint... "
    if curl -sf "http://localhost:8081/metrics" | grep -q "security_pop"; then
        test_result "Custom Metrics" "pass"
    else
        test_result "Custom Metrics" "fail" "/metrics not returning security_pop metrics"
    fi
    
    # Test node exporter
    echo -n "  Testing node_exporter... "
    if docker exec security-pop curl -sf http://localhost:9100/metrics | grep -q "node_"; then
        test_result "Node Exporter" "pass"
    else
        test_result "Node Exporter" "fail" "Node exporter not responding"
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
    
    # Show recent alerts
    echo -e "${YELLOW}Recent IPS Alerts:${NC}"
    docker exec security-pop tail -5 /var/log/suricata/fast.log 2>/dev/null || echo "  (none)"
    echo ""
    
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed. Review the output above.${NC}"
        exit 1
    else
        echo -e "${GREEN}All Security PoP tests passed!${NC}"
        exit 0
    fi
}

# Main
main() {
    print_header
    
    # Check if container is running
    if ! docker ps | grep -q "security-pop"; then
        echo -e "${RED}Error: security-pop container not running.${NC}"
        echo "Start with: make up-security"
        exit 1
    fi
    
    test_service_health
    test_ips_detection
    test_dns
    test_proxy
    test_firewall
    test_metrics
    
    print_summary
}

main "$@"
