#!/bin/bash
# FlexiWAN API Automation Script
# Automates as much as possible via API, documents manual steps

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Load environment
if [ -f "$PROJECT_DIR/.env" ]; then
    source "$PROJECT_DIR/.env"
fi

CONTROLLER_URL="${FLEXIWAN_CONTROLLER_URL:-http://localhost:3000}"
ADMIN_EMAIL="${FLEXIWAN_ADMIN_EMAIL:-admin@opensase.lab}"
ADMIN_PASSWORD="${FLEXIWAN_ADMIN_PASSWORD:-changeme_flexiwan}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_manual() { echo -e "${CYAN}[MANUAL]${NC} $1"; }

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  FlexiWAN API Automation${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# Step 1: Wait for controller
wait_for_controller() {
    log_info "Step 1: Checking controller availability..."
    
    for i in {1..30}; do
        if curl -sf "${CONTROLLER_URL}/api/health" > /dev/null 2>&1; then
            log_info "Controller is available at ${CONTROLLER_URL}"
            return 0
        fi
        sleep 2
    done
    
    log_error "Controller not responding. Please ensure it's running."
    log_manual "Start with: docker compose up -d flexiwan-mongo flexiwan-controller"
    return 1
}

# Step 2: Authenticate
authenticate() {
    log_info "Step 2: Authenticating with controller..."
    
    AUTH_RESPONSE=$(curl -sf -X POST "${CONTROLLER_URL}/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"${ADMIN_EMAIL}\", \"password\": \"${ADMIN_PASSWORD}\"}" 2>&1) || true
    
    TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.token // empty' 2>/dev/null)
    
    if [ -n "$TOKEN" ]; then
        log_info "Authentication successful"
        echo "$TOKEN"
        return 0
    else
        log_warn "Could not authenticate via API"
        log_manual "Please create admin account in FlexiWAN UI:"
        log_manual "  1. Open ${CONTROLLER_URL}"
        log_manual "  2. Create account with email: ${ADMIN_EMAIL}"
        log_manual "  3. Set password and update FLEXIWAN_ADMIN_PASSWORD in .env"
        return 1
    fi
}

# Step 3: Get/Create Organization
setup_organization() {
    local token="$1"
    log_info "Step 3: Setting up organization..."
    
    # Try to get existing org
    ORG_RESPONSE=$(curl -sf "${CONTROLLER_URL}/api/organizations" \
        -H "Authorization: Bearer ${token}" 2>/dev/null) || true
    
    ORG_ID=$(echo "$ORG_RESPONSE" | jq -r '.[0]._id // empty' 2>/dev/null)
    
    if [ -n "$ORG_ID" ]; then
        log_info "Found existing organization: $ORG_ID"
        echo "$ORG_ID"
        return 0
    fi
    
    # Try to create org
    CREATE_RESPONSE=$(curl -sf -X POST "${CONTROLLER_URL}/api/organizations" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d '{"name": "OpenSASE Lab", "description": "SASE Security Lab"}' 2>/dev/null) || true
    
    ORG_ID=$(echo "$CREATE_RESPONSE" | jq -r '._id // empty' 2>/dev/null)
    
    if [ -n "$ORG_ID" ]; then
        log_info "Created organization: $ORG_ID"
        echo "$ORG_ID"
        return 0
    fi
    
    log_warn "Could not create organization via API"
    log_manual "Please create organization in FlexiWAN UI:"
    log_manual "  1. Go to Settings → Organizations"
    log_manual "  2. Click 'Add Organization'"
    log_manual "  3. Name: OpenSASE Lab"
    return 1
}

# Step 4: Create Segments (VRF)
setup_segments() {
    local token="$1"
    local org_id="$2"
    
    log_info "Step 4: Setting up network segments..."
    
    # Corp segment
    CORP_RESPONSE=$(curl -sf -X POST "${CONTROLLER_URL}/api/organizations/${org_id}/segments" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d '{"name": "corp", "segmentId": 1, "description": "Corporate traffic"}' 2>/dev/null) || true
    
    if echo "$CORP_RESPONSE" | jq -e '.name' > /dev/null 2>&1; then
        log_info "Created corp segment (ID: 1)"
    else
        log_warn "Corp segment may already exist or API limited"
    fi
    
    # Guest segment
    GUEST_RESPONSE=$(curl -sf -X POST "${CONTROLLER_URL}/api/organizations/${org_id}/segments" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d '{"name": "guest", "segmentId": 2, "description": "Guest traffic"}' 2>/dev/null) || true
    
    if echo "$GUEST_RESPONSE" | jq -e '.name' > /dev/null 2>&1; then
        log_info "Created guest segment (ID: 2)"
    else
        log_warn "Guest segment may already exist or API limited"
    fi
    
    log_manual "Verify segments in UI: Settings → Segments"
}

# Step 5: Generate Device Tokens
generate_tokens() {
    local token="$1"
    local org_id="$2"
    
    log_info "Step 5: Generating device tokens..."
    
    TOKEN_FILE="$PROJECT_DIR/.device-tokens"
    > "$TOKEN_FILE"  # Clear file
    
    for branch in branch-a branch-b branch-c; do
        TOKEN_RESPONSE=$(curl -sf -X POST "${CONTROLLER_URL}/api/organizations/${org_id}/devices/tokens" \
            -H "Authorization: Bearer ${token}" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"${branch}\"}" 2>/dev/null) || true
        
        DEVICE_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token // empty' 2>/dev/null)
        
        if [ -n "$DEVICE_TOKEN" ]; then
            echo "${branch}=${DEVICE_TOKEN}" >> "$TOKEN_FILE"
            log_info "Generated token for ${branch}"
        else
            echo "${branch}=MANUAL_REQUIRED" >> "$TOKEN_FILE"
            log_warn "Could not generate token for ${branch} via API"
        fi
    done
    
    log_manual "If tokens failed, generate manually:"
    log_manual "  1. Go to Inventory → Device Tokens"
    log_manual "  2. Click 'Create Token' for each branch"
    log_manual "  3. Copy tokens to .device-tokens file"
}

# Step 6: Document Manual Steps
print_manual_steps() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Required Manual Steps${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    
    echo "The following steps MUST be done in FlexiWAN UI:"
    echo ""
    echo "1. DEVICE APPROVAL"
    echo "   - Start edges: docker compose up -d branch-a branch-b branch-c"
    echo "   - Go to: Inventory → Devices"
    echo "   - Click each pending device → Approve"
    echo ""
    echo "2. INTERFACE CONFIGURATION"
    echo "   For each device:"
    echo "   - Click device → Interfaces tab"
    echo "   - Set eth0 as WAN1 (Primary)"
    echo "   - Set eth1 as WAN2 (Backup)"
    echo "   - Set eth2 as LAN"
    echo "   - Click Apply"
    echo ""
    echo "3. TUNNEL CREATION"
    echo "   - Go to: Tunnels"
    echo "   - Create tunnel: branch-a ↔ pop-gateway"
    echo "   - Create tunnel: branch-b ↔ pop-gateway"
    echo "   - Create tunnel: branch-c ↔ pop-gateway"
    echo ""
    echo "4. POLICY APPLICATION"
    echo "   For each device:"
    echo "   - Click device → Policies tab"
    echo "   - Enable 'corp-via-pop' for corp segment"
    echo "   - Enable 'guest-local-breakout' for guest segment"
    echo "   - Click Apply"
    echo ""
    echo "Full documentation: docs/FLEXIWAN_MANUAL_ENROLLMENT.md"
    echo ""
}

# Step 7: List API Capabilities
print_api_reference() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Available API Endpoints${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "Endpoints that CAN be automated:"
    echo "  POST /api/auth/login - Authentication"
    echo "  GET  /api/devices - List devices"
    echo "  GET  /api/devices/{id} - Device details"
    echo "  GET  /api/tunnels - List tunnels"
    echo "  GET  /api/organizations - List orgs"
    echo "  POST /api/organizations - Create org"
    echo "  GET  /api/devices/{id}/status - Device status"
    echo ""
    echo "Endpoints NOT available in OSS:"
    echo "  ✗ Device approval (UI only)"
    echo "  ✗ Interface configuration (UI only)"
    echo "  ✗ Tunnel creation (UI only)"
    echo "  ✗ Policy application (UI only)"
    echo ""
}

# Main
main() {
    print_header
    
    # Execute automation steps
    wait_for_controller || exit 1
    
    TOKEN=$(authenticate) || {
        print_manual_steps
        print_api_reference
        exit 1
    }
    
    ORG_ID=$(setup_organization "$TOKEN") || {
        print_manual_steps
        print_api_reference
        exit 1
    }
    
    setup_segments "$TOKEN" "$ORG_ID"
    generate_tokens "$TOKEN" "$ORG_ID"
    
    print_manual_steps
    print_api_reference
    
    echo -e "${GREEN}Automation complete.${NC}"
    echo "Device tokens saved to: .device-tokens"
    echo ""
    echo "Next: Complete manual steps in FlexiWAN UI (${CONTROLLER_URL})"
}

main "$@"
