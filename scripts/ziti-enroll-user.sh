#!/bin/bash
# OpenZiti User Enrollment Script
# Enrolls a user identity for Ziti access

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }

IDENTITIES_DIR="$PROJECT_DIR/docker/openziti-identities"

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  OpenZiti User Enrollment${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# Enroll using ziti CLI
enroll_identity() {
    local jwt_file="$1"
    local identity_name=$(basename "$jwt_file" .jwt)
    local output_file="$IDENTITIES_DIR/${identity_name}.json"
    
    log_info "Enrolling identity: $identity_name"
    
    # Use ziti-edge-tunnel or ziti CLI for enrollment
    if command -v ziti &> /dev/null; then
        ziti edge enroll --jwt "$jwt_file" --out "$output_file"
        log_info "Enrolled to: $output_file"
    else
        # Use Docker if local ziti not available
        docker run --rm \
            -v "$IDENTITIES_DIR:/identities" \
            openziti/ziti-edge-tunnel \
            enroll --jwt "/identities/${identity_name}.jwt" \
            --out "/identities/${identity_name}.json"
        log_info "Enrolled to: $output_file"
    fi
}

# Print client setup instructions
print_client_setup() {
    local identity_file="$1"
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Client Setup Guide${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "Your enrolled identity: $identity_file"
    echo ""
    echo "Option 1: Ziti Desktop Edge (GUI)"
    echo "  1. Download from: https://openziti.io/docs/downloads"
    echo "  2. Install and run Ziti Desktop Edge"
    echo "  3. Click 'Add Identity' → Import file:"
    echo "     $identity_file"
    echo "  4. Connect the identity"
    echo ""
    echo "Option 2: Ziti Edge Tunnel (CLI)"
    echo "  # macOS"
    echo "  brew install openziti/tap/ziti-edge-tunnel"
    echo "  sudo ziti-edge-tunnel run --identity $identity_file"
    echo ""
    echo "  # Linux"
    echo "  curl -sS https://get.openziti.io/install.bash | sudo bash"
    echo "  sudo ziti-edge-tunnel run --identity $identity_file"
    echo ""
    echo "  # Docker"
    echo "  docker run -it --rm \\"
    echo "    --cap-add NET_ADMIN \\"
    echo "    --device /dev/net/tun \\"
    echo "    -v $IDENTITIES_DIR:/identities \\"
    echo "    openziti/ziti-edge-tunnel \\"
    echo "    run --identity /identities/$(basename $identity_file)"
    echo ""
    echo "Option 3: Test with ziti CLI"
    echo "  ziti edge login localhost:1280 -u admin -p \$ZITI_PWD"
    echo "  # Then use ziti demo for testing"
    echo ""
    echo "After connecting, access services:"
    echo "  curl http://app1.ziti"
    echo "  curl http://app2.ziti/get"
    echo ""
}

# Main
main() {
    print_header
    
    # Check for JWT files
    if [ ! -d "$IDENTITIES_DIR" ]; then
        echo "Error: No identities directory found"
        echo "Run ./scripts/ziti-bootstrap.sh first"
        exit 1
    fi
    
    # Find JWT files
    JWT_FILES=$(find "$IDENTITIES_DIR" -name "*.jwt" 2>/dev/null)
    
    if [ -z "$JWT_FILES" ]; then
        echo "No JWT enrollment tokens found"
        echo "Run ./scripts/ziti-bootstrap.sh first"
        exit 1
    fi
    
    echo "Available enrollment tokens:"
    for jwt in $JWT_FILES; do
        echo "  - $(basename $jwt)"
    done
    echo ""
    
    # Default to testuser
    DEFAULT_JWT="$IDENTITIES_DIR/testuser.jwt"
    
    if [ -f "$DEFAULT_JWT" ]; then
        log_info "Enrolling default test user..."
        enroll_identity "$DEFAULT_JWT"
        print_client_setup "$IDENTITIES_DIR/testuser.json"
    else
        echo "Select a JWT file to enroll:"
        select jwt in $JWT_FILES; do
            enroll_identity "$jwt"
            print_client_setup "${jwt%.jwt}.json"
            break
        done
    fi
}

main "$@"
