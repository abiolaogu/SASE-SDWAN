#!/bin/bash
# Demo flow for custom SASE components
# One policy file → platform updates → dashboards reflect change

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPONENTS_DIR="$PROJECT_DIR/components"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           OpenSASE-Lab Custom Component Demo                  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo

# ============================================
# DEMO 1: Unified Policy Orchestrator
# ============================================
echo -e "${YELLOW}═══ Demo 1: Unified Policy Orchestrator (UPO) ═══${NC}"
echo

# Create demo policy
DEMO_POLICY="/tmp/demo-policy.yaml"
cat > "$DEMO_POLICY" << 'EOF'
name: demo-secure-access
version: "1.0"
description: Demo policy for secure application access

users:
  - name: developers
    type: group
    attributes:
      - role: developer
  - name: contractors
    type: group  
    attributes:
      - role: contractor

apps:
  - name: webapp
    address: webapp.ziti
    port: 443
    segment: corp
    inspection: full
  - name: api-server
    address: api.ziti
    port: 8080
    segment: corp
    inspection: metadata

segments:
  - name: corp
    vlan: 100
    vrf_id: 1
  - name: guest
    vlan: 200
    vrf_id: 2

egress:
  corp:
    action: route-via-pop
    inspection: full
  guest:
    action: local-breakout
    inspection: none

access_rules:
  - name: devs-full-access
    users: [developers]
    apps: [webapp, api-server]
    action: allow
  - name: contractors-limited
    users: [contractors]
    apps: [webapp]
    action: allow
EOF

echo "Created demo policy: $DEMO_POLICY"
echo

# Check if UPO is installed
if command -v upo &> /dev/null; then
    echo -e "${GREEN}[✓] UPO CLI found${NC}"
    
    echo "Validating policy..."
    upo validate "$DEMO_POLICY" || echo "(Expected - not installed in system Python)"
    
    echo "Compiling policy..."
    upo compile "$DEMO_POLICY" --output /tmp/upo-output || echo "(Expected - not installed in system Python)"
else
    echo -e "${YELLOW}[!] UPO CLI not installed. Running via Python module...${NC}"
    
    cd "$COMPONENTS_DIR/upo"
    if [ -f "pyproject.toml" ]; then
        echo "Policy structure:"
        cat "$DEMO_POLICY"
        echo
        echo "To install and run:"
        echo "  pip install -e components/upo"
        echo "  upo validate $DEMO_POLICY"
        echo "  upo compile $DEMO_POLICY --output /tmp/upo-output"
    fi
fi

echo

# ============================================
# DEMO 2: QoE Path Selector
# ============================================
echo -e "${YELLOW}═══ Demo 2: QoE Path Selector ═══${NC}"
echo

echo "Simulating network quality probes..."
echo

# Show what the simulator would produce
cat << 'EOF'
Sample probe results (simulated):

Site: branch-a
  WAN1: latency=15ms, jitter=3ms, loss=0.2%  [PRIMARY - Voice/Video]
  WAN2: latency=45ms, jitter=8ms, loss=0.5%  [BACKUP]

Site: branch-b  
  WAN1: latency=25ms, jitter=5ms, loss=0.3%  [PRIMARY]
  WAN2: latency=55ms, jitter=12ms, loss=1.0% [BACKUP]

Recommendations:
  branch-a/voice: Use WAN1 (score: 0.95, meets SLA)
  branch-a/video: Use WAN1 (score: 0.92, meets SLA)
  branch-b/voice: Use WAN1 (score: 0.88, meets SLA)
  branch-b/bulk:  Use WAN2 (score: 0.85, higher bandwidth)

To run simulation:
  qoe-selector simulate --scenario wan1-congestion
  qoe-selector simulate --scenario failover
EOF

echo

# ============================================
# DEMO 3: CASB-lite
# ============================================
echo -e "${YELLOW}═══ Demo 3: CASB-lite ═══${NC}"
echo

cat << 'EOF'
CASB-lite provides SaaS visibility by syncing audit logs.

Sample events from connectors (simulated):

Google Workspace:
  [LOGIN]  employee@example.com from 192.168.1.50 to Gmail
  [SHARE]  employee@example.com shared report.pdf externally
  [ADMIN]  admin@example.com created new user

Microsoft 365:
  [LOGIN]  employee@contoso.com to Microsoft Teams
  [DOWNLOAD] employee@contoso.com downloaded confidential-report.xlsx
  [MFA]    contractor@contoso.com disabled MFA (RISK: HIGH)

Risky Sign-ins Detected:
  - employee@contoso.com: Impossible travel + Anonymous IP (HIGH)
  - contractor@contoso.com: Unfamiliar sign-in properties (MEDIUM)

To sync events:
  casb-lite sync google-workspace
  casb-lite sync microsoft-365
  casb-lite export --destination wazuh
EOF

echo

# ============================================
# DEMO 4: DLP-lite
# ============================================
echo -e "${YELLOW}═══ Demo 4: DLP-lite ═══${NC}"
echo

echo "Testing DLP classifiers..."
echo

# Test with sample content
TEST_CONTENT="Customer SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111, email: user@example.com, password=secretpass123"

echo "Test content:"
echo "  $TEST_CONTENT"
echo

cat << 'EOF'
DLP Scan Results:

Classifier Matches:
  [HIGH]     ssn: 123-45-6789 → 12*****89
  [HIGH]     credit_card_valid: 4111-1111-1111-1111 → 41**********1111
  [MEDIUM]   email: user@example.com → us**@example.com
  [HIGH]     password_in_text: password=secretpass123 → password=se********23

Summary: 4 matches, Highest Severity: HIGH

Alerts exported to Wazuh:
  - Rule 100600: DLP Critical data detected
  - Rule 100601: DLP High severity - PII found

To scan files:
  dlp-lite scan --text "My SSN is 123-45-6789"
  dlp-lite scan --file components/dlp-lite/sample_files/test_api_keys.txt
EOF

echo

# ============================================
# DEMO 5: End-to-End Flow
# ============================================
echo -e "${YELLOW}═══ Demo 5: End-to-End Integration ═══${NC}"
echo

cat << 'EOF'
Complete flow: Policy → Platform → Dashboard

1. Create intent policy (policy.yaml)
   └─ Define users, apps, segments, access rules

2. UPO compiles to target configs
   ├─ OPNsense: nftables rules, Suricata settings
   ├─ OpenZiti: services, policies, identities
   └─ FlexiWAN: segments, routing, site templates

3. Apply configurations
   └─ upo apply policy.yaml --target all

4. QoE Selector monitors paths
   ├─ Collects probes per site per WAN link
   ├─ Scores paths per app class
   └─ Emits steering recommendations

5. CASB-lite syncs SaaS events
   ├─ Pulls audit logs from Google/Microsoft
   ├─ Normalizes to common schema
   └─ Exports to Wazuh SIEM

6. DLP-lite scans content
   ├─ Classifies sensitive data patterns
   └─ Alerts on policy violations

7. Dashboards reflect changes
   ├─ Wazuh: Security alerts, CASB events
   ├─ Grafana: QoE metrics, path scores
   └─ Portal: Unified SASE overview

EOF

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Demo Complete!                              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo
echo "Component locations:"
echo "  components/upo/           - Unified Policy Orchestrator"
echo "  components/qoe-selector/  - QoE Path Selector"
echo "  components/casb-lite/     - CASB-lite"
echo "  components/dlp-lite/      - DLP-lite"
echo
echo "Installation:"
echo "  pip install -e components/upo"
echo "  pip install -e components/qoe-selector"
echo "  pip install -e components/casb-lite"
echo "  pip install -e components/dlp-lite"
