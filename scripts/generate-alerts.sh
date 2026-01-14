#!/bin/bash
# Synthetic Alert Generator for OpenSASE-Lab
# Generates safe, non-malicious alerts for demo purposes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_alert() { echo -e "${YELLOW}[ALERT]${NC} $1"; }

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Synthetic Alert Generator${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "This script generates SAFE, non-malicious alerts"
    echo "for demonstration and testing purposes."
    echo ""
}

# ============================================
# Suricata Alert Generation
# ============================================

generate_suricata_alerts() {
    log_info "Generating Suricata IPS alerts..."
    
    # Trigger test rules via HTTP requests
    for i in {1..3}; do
        # User-Agent test (triggers SID 9000002)
        curl -s -H 'User-Agent: OpenSASE-Test' http://localhost:8081/test > /dev/null 2>&1 || true
        
        # Header test (triggers SID 9000003)
        curl -s -H 'X-OpenSASE-Test: demo' http://localhost:8081/demo > /dev/null 2>&1 || true
        
        sleep 1
    done
    
    log_alert "Generated 6 Suricata test alerts"
}

# ============================================
# DNS Alert Generation  
# ============================================

generate_dns_alerts() {
    log_info "Generating DNS alerts..."
    
    # Query test domains that trigger rules
    docker exec security-pop dig @localhost test.opensase.lab +short 2>/dev/null || true
    docker exec security-pop dig @localhost blocked.demo.lab +short 2>/dev/null || true
    docker exec security-pop dig @localhost app1.ziti +short 2>/dev/null || true
    
    log_alert "Generated 3 DNS test alerts"
}

# ============================================
# Synthetic Wazuh Alerts
# ============================================

generate_wazuh_synthetic_alerts() {
    log_info "Generating synthetic Wazuh alerts..."
    
    # Send synthetic events to Wazuh via syslog
    WAZUH_SYSLOG="wazuh-manager"
    
    # IDS Alert (Synthetic)
    docker exec security-pop logger -p local0.warning \
        'OPENSASE-SYNTHETIC-ALERT: type=ids message="Synthetic IPS detection for demo"' 2>/dev/null || true
    
    # Auth Failure (Synthetic)
    docker exec security-pop logger -p local0.warning \
        'OPENSASE-SYNTHETIC-ALERT: type=auth_failure message="Simulated authentication failure"' 2>/dev/null || true
    
    # Network Event (Synthetic)
    docker exec security-pop logger -p local0.info \
        'OPENSASE-SYNTHETIC-ALERT: type=network message="Simulated tunnel failover event"' 2>/dev/null || true
    
    # Config Change (Synthetic)
    docker exec security-pop logger -p local0.notice \
        'OPENSASE-SYNTHETIC-ALERT: type=config_change message="Simulated policy update"' 2>/dev/null || true
    
    # Correlation Event (Synthetic)
    docker exec security-pop logger -p local0.warning \
        'OPENSASE-TEST-EVENT: auth_attempt 192.168.1.100 failed' 2>/dev/null || true
    docker exec security-pop logger -p local0.warning \
        'OPENSASE-TEST-EVENT: auth_attempt 192.168.1.100 failed' 2>/dev/null || true
    docker exec security-pop logger -p local0.warning \
        'OPENSASE-TEST-EVENT: auth_attempt 192.168.1.100 failed' 2>/dev/null || true
    
    log_alert "Generated 7 synthetic Wazuh alerts"
}

# ============================================
# FlexiWAN Event Simulation
# ============================================

generate_flexiwan_events() {
    log_info "Generating FlexiWAN event simulations..."
    
    # Generate JSON events to log file
    LOG_FILE="/tmp/flexiwan-events.json"
    
    cat > "$LOG_FILE" << 'EOF'
{"event":"device_connected","device_name":"branch-a","timestamp":"2024-01-01T12:00:00Z"}
{"event":"tunnel_up","tunnel_name":"branch-a-to-pop","device_name":"branch-a","timestamp":"2024-01-01T12:00:01Z"}
{"event":"wan_failover","device_name":"branch-b","from_wan":"wan1","to_wan":"wan2","timestamp":"2024-01-01T12:00:02Z"}
{"event":"policy_applied","policy_name":"corp-via-pop","device_name":"branch-a","timestamp":"2024-01-01T12:00:03Z"}
EOF
    
    # Copy to Wazuh if container is running
    docker cp "$LOG_FILE" wazuh-manager:/var/log/flexiwan/events.json 2>/dev/null || {
        mkdir -p "$PROJECT_DIR/docker/wazuh/logs"
        cp "$LOG_FILE" "$PROJECT_DIR/docker/wazuh/logs/flexiwan-events.json"
    }
    
    log_alert "Generated 4 FlexiWAN event simulations"
}

# ============================================
# OpenZiti Event Simulation
# ============================================

generate_ziti_events() {
    log_info "Generating OpenZiti event simulations..."
    
    LOG_FILE="/tmp/ziti-events.json"
    
    cat > "$LOG_FILE" << 'EOF'
{"timestamp":"2024-01-01T12:00:00Z","event_type":"edge.sessions","identity":"testuser","service":"app1"}
{"timestamp":"2024-01-01T12:00:01Z","event_type":"edge.sessions","identity":"testuser","service":"app2"}
{"timestamp":"2024-01-01T12:00:02Z","event_type":"authentication.failed","identity":"unknown-user","reason":"invalid certificate"}
{"timestamp":"2024-01-01T12:00:03Z","event_type":"identity.created","identity.name":"new-employee"}
{"timestamp":"2024-01-01T12:00:04Z","event_type":"fabric.routers","router.name":"router-a","router.isOnline":true}
EOF
    
    docker cp "$LOG_FILE" wazuh-manager:/var/log/ziti/events.json 2>/dev/null || {
        mkdir -p "$PROJECT_DIR/docker/wazuh/logs"
        cp "$LOG_FILE" "$PROJECT_DIR/docker/wazuh/logs/ziti-events.json"
    }
    
    log_alert "Generated 5 OpenZiti event simulations"
}

# ============================================
# File Integrity Alert
# ============================================

generate_fim_alert() {
    log_info "Generating File Integrity alert..."
    
    # Create and modify a test file to trigger FIM
    docker exec security-pop touch /etc/opensase-test-file 2>/dev/null || true
    docker exec security-pop rm -f /etc/opensase-test-file 2>/dev/null || true
    
    log_alert "Generated FIM test event"
}

# ============================================
# Summary
# ============================================

print_summary() {
    local total=${1:-0}
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Alert Generation Complete${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "Total synthetic alerts generated: ~25"
    echo ""
    echo "Alert types generated:"
    echo "  - Suricata IPS alerts (6)"
    echo "  - DNS security alerts (3)"
    echo "  - Wazuh synthetic alerts (7)"
    echo "  - FlexiWAN events (4)"
    echo "  - OpenZiti events (5)"
    echo "  - File integrity events (1)"
    echo ""
    echo "View alerts in:"
    echo "  - Wazuh Dashboard: http://localhost:5601"
    echo "  - Suricata fast.log: docker exec security-pop tail /var/log/suricata/fast.log"
    echo "  - Wazuh alerts: docker exec wazuh-manager tail /var/ossec/logs/alerts/alerts.json"
    echo ""
    echo "Note: Some alerts may take a few seconds to appear in Wazuh."
}

# ============================================
# Main
# ============================================

main() {
    print_header
    
    # Check containers are running
    if ! docker ps | grep -q "security-pop"; then
        echo "Warning: security-pop container not running"
        echo "Some alerts may not be generated"
    fi
    
    generate_suricata_alerts
    sleep 2
    
    generate_dns_alerts
    sleep 1
    
    generate_wazuh_synthetic_alerts
    sleep 1
    
    generate_flexiwan_events
    sleep 1
    
    generate_ziti_events
    sleep 1
    
    generate_fim_alert
    
    print_summary
}

# Allow specific alert types
case "${1:-all}" in
    suricata)
        generate_suricata_alerts
        ;;
    dns)
        generate_dns_alerts
        ;;
    wazuh)
        generate_wazuh_synthetic_alerts
        ;;
    flexiwan)
        generate_flexiwan_events
        ;;
    ziti)
        generate_ziti_events
        ;;
    fim)
        generate_fim_alert
        ;;
    all|*)
        main
        ;;
esac
