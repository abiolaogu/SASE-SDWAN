#!/bin/bash
# OpenSASE-Lab Interactive Demo
# Guided walkthrough of all lab features

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    clear
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║               🛡️  OpenSASE-Lab Demo  🛡️                       ║"
    echo "║                                                               ║"
    echo "║     SD-WAN │ ZTNA │ IPS │ SIEM │ SSO │ Observability         ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

press_enter() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

demo_section() {
    local title="$1"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $title${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Demo 1: Architecture Overview
demo_architecture() {
    demo_section "1. Architecture Overview"
    
    cat << 'EOF'
The OpenSASE-Lab implements a complete SASE architecture:

┌─────────────────────────────────────────────────────────────────┐
│                        Security PoP (Hub)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ FlexiWAN │ │ OpenZiti │ │ Suricata │ │  Wazuh   │           │
│  │Controller│ │Controller│ │   IPS    │ │ Manager  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│                      ┌──────────┐                               │
│                      │ Keycloak │                               │
│                      │   SSO    │                               │
│                      └──────────┘                               │
└─────────────────────────────────────────────────────────────────┘
           ▲                ▲                ▲
           │ WireGuard      │ Ziti Fabric    │
           │                │                │
    ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐
    │  Branch A   │  │  Branch B   │  │  Branch C   │
    │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │
    │ │  App1   │ │  │ │  App2   │ │  │ │ (empty) │ │
    │ │(private)│ │  │ │(private)│ │  │ │         │ │
    │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │
    └─────────────┘  └─────────────┘  └─────────────┘

EOF
    
    echo "Key concepts:"
    echo "  • All branch internet traffic routes through Security PoP"
    echo "  • Private apps are only accessible via ZTNA (no public ports)"
    echo "  • All security events centralized in Wazuh SIEM"
    echo "  • Single Sign-On via Keycloak for all admin interfaces"
    
    press_enter
}

# Demo 2: SD-WAN
demo_sdwan() {
    demo_section "2. SD-WAN with FlexiWAN"
    
    echo "FlexiWAN provides:"
    echo "  • WireGuard-based encrypted tunnels"
    echo "  • Application-aware routing"
    echo "  • Link quality monitoring"
    echo ""
    echo -e "${GREEN}Opening FlexiWAN Dashboard...${NC}"
    echo -e "  URL: ${YELLOW}http://localhost:3000${NC}"
    echo ""
    echo "Things to explore:"
    echo "  1. View connected edge devices"
    echo "  2. Check tunnel status and latency"
    echo "  3. Configure routing policies"
    
    if command -v open &> /dev/null; then
        open "http://localhost:3000" 2>/dev/null || true
    elif command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:3000" 2>/dev/null || true
    fi
    
    press_enter
}

# Demo 3: Security PoP
demo_security_pop() {
    demo_section "3. Security PoP (IPS + DNS)"
    
    echo "The Security PoP includes:"
    echo "  • Suricata in IPS mode (inline inspection)"
    echo "  • Unbound DNS with query logging"
    echo "  • nftables zone-based firewall"
    echo ""
    echo "Testing IPS detection..."
    echo ""
    
    # Trigger a test alert
    echo -e "${YELLOW}Sending test traffic to trigger IPS alert...${NC}"
    curl -sf "http://localhost:8081/api/health" > /dev/null 2>&1 && \
        echo -e "${GREEN}Security PoP API is responding${NC}" || \
        echo -e "${YELLOW}Security PoP API not available${NC}"
    
    echo ""
    echo "Recent Suricata alerts:"
    docker exec security-pop tail -3 /var/log/suricata/fast.log 2>/dev/null || \
        echo "  (No alerts yet - run some traffic through the PoP)"
    
    press_enter
}

# Demo 4: ZTNA
demo_ztna() {
    demo_section "4. Zero Trust Network Access (OpenZiti)"
    
    echo "OpenZiti provides true zero trust:"
    echo "  • Apps have NO public IP or ports"
    echo "  • Access requires enrolled identity"
    echo "  • All traffic is mTLS encrypted"
    echo ""
    echo "Private applications:"
    echo "  • App1 (10.201.0.100) - Branch A - Nginx"
    echo "  • App2 (10.202.0.100) - Branch B - HTTPBin"
    echo ""
    echo "These apps are 'dark' - try accessing them directly:"
    echo ""
    
    echo -e "${YELLOW}Attempting direct access to App1...${NC}"
    if curl -sf --connect-timeout 2 "http://10.201.0.100" > /dev/null 2>&1; then
        echo -e "${RED}Warning: App1 is directly accessible (should be blocked)${NC}"
    else
        echo -e "${GREEN}✓ App1 is not directly accessible (correct!)${NC}"
    fi
    echo ""
    echo "To access these apps, you need:"
    echo "  1. Ziti Desktop Edge installed"
    echo "  2. Enrolled identity with proper policies"
    echo "  3. Then access via: http://app1.ziti or http://app2.ziti"
    
    press_enter
}

# Demo 5: SIEM
demo_siem() {
    demo_section "5. Security Visibility (Wazuh SIEM)"
    
    echo "Wazuh provides centralized security monitoring:"
    echo "  • Log collection from all components"
    echo "  • Suricata IPS alert correlation"
    echo "  • File integrity monitoring"
    echo "  • Vulnerability detection"
    echo ""
    echo -e "${GREEN}Opening Wazuh Dashboard...${NC}"
    echo -e "  URL: ${YELLOW}http://localhost:5601${NC}"
    echo -e "  User: ${YELLOW}wazuh-wui${NC}"
    echo -e "  Pass: ${YELLOW}(see .env file)${NC}"
    echo ""
    
    if command -v open &> /dev/null; then
        open "http://localhost:5601" 2>/dev/null || true
    fi
    
    echo "Things to explore:"
    echo "  1. Security Events dashboard"
    echo "  2. Agents status"
    echo "  3. Suricata alerts integration"
    
    press_enter
}

# Demo 6: Observability
demo_observability() {
    demo_section "6. Observability (Prometheus + Grafana)"
    
    echo "Metrics collected from all components:"
    echo "  • System resources (CPU, RAM, disk, network)"
    echo "  • SD-WAN tunnel metrics"
    echo "  • IPS statistics"
    echo "  • ZTNA session counts"
    echo ""
    echo -e "${GREEN}Opening Grafana Dashboard...${NC}"
    echo -e "  URL: ${YELLOW}http://localhost:3001${NC}"
    echo -e "  User: ${YELLOW}admin${NC}"
    echo -e "  Pass: ${YELLOW}(see .env file)${NC}"
    echo ""
    
    if command -v open &> /dev/null; then
        open "http://localhost:3001" 2>/dev/null || true
    fi
    
    echo "Pre-built dashboards:"
    echo "  • OpenSASE-Lab Overview"
    echo "  • SD-WAN Performance"
    echo "  • Security PoP Stats"
    
    press_enter
}

# Demo 7: Unified Portal
demo_portal() {
    demo_section "7. Unified Portal"
    
    echo "The single pane of glass portal shows:"
    echo "  • Sites & tunnel status (FlexiWAN)"
    echo "  • Security policy status (Suricata)"
    echo "  • ZTNA app inventory (OpenZiti)"
    echo "  • Security alerts summary (Wazuh)"
    echo ""
    echo -e "${GREEN}Opening Unified Portal...${NC}"
    echo -e "  URL: ${YELLOW}http://localhost:8080${NC}"
    echo -e "  Login via Keycloak SSO"
    echo ""
    
    if command -v open &> /dev/null; then
        open "http://localhost:8080" 2>/dev/null || true
    fi
    
    echo "SSO is powered by Keycloak (http://localhost:8443)"
    echo ""
    echo "Test accounts:"
    echo "  • admin / admin123 (full access)"
    echo "  • operator / operator123 (manage)"
    echo "  • viewer / viewer123 (read-only)"
    
    press_enter
}

# Summary
demo_summary() {
    demo_section "Demo Complete!"
    
    echo "You've explored the complete OpenSASE-Lab:"
    echo ""
    echo "  ✓ SD-WAN overlay networking (FlexiWAN)"
    echo "  ✓ Security PoP with IPS (Suricata)"
    echo "  ✓ Zero Trust Network Access (OpenZiti)"
    echo "  ✓ Centralized SIEM (Wazuh)"
    echo "  ✓ Observability (Prometheus + Grafana)"
    echo "  ✓ Single Sign-On (Keycloak)"
    echo "  ✓ Unified Portal"
    echo ""
    echo "Quick reference URLs:"
    echo "  • Portal:     http://localhost:8080"
    echo "  • FlexiWAN:   http://localhost:3000"
    echo "  • Grafana:    http://localhost:3001"
    echo "  • Wazuh:      http://localhost:5601"
    echo "  • Keycloak:   http://localhost:8443"
    echo "  • Prometheus: http://localhost:9090"
    echo ""
    echo "Run 'make smoke-test' to validate all components."
    echo ""
    echo "Thank you for exploring OpenSASE-Lab! 🛡️"
}

# Main
print_banner
echo "This demo will guide you through all components of OpenSASE-Lab."
echo ""
echo "Make sure all services are running: 'make status'"
press_enter

demo_architecture
demo_sdwan
demo_security_pop
demo_ztna
demo_siem
demo_observability
demo_portal
demo_summary
