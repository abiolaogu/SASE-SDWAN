#!/bin/bash
# OpenZiti Bootstrap Script
# Initializes controller, creates services, policies, and test identities

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Ziti CLI wrapper
ziti_cli() {
    docker exec ziti-controller ziti "$@"
}

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  OpenZiti ZTNA Bootstrap${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# Wait for controller
wait_for_controller() {
    log_info "Step 1: Waiting for Ziti controller..."
    
    for i in {1..60}; do
        if docker exec ziti-controller curl -sf -k https://localhost:1280/edge/v1/version > /dev/null 2>&1; then
            log_info "Controller is ready"
            return 0
        fi
        sleep 2
    done
    
    log_error "Controller not ready after 120 seconds"
    return 1
}

# Login to controller
login_controller() {
    log_info "Step 2: Logging into controller..."
    
    ZITI_PWD="${ZITI_PWD:-admin}"
    
    ziti_cli edge login localhost:1280 \
        -u admin \
        -p "$ZITI_PWD" \
        -y 2>/dev/null || {
        log_error "Failed to login to controller"
        return 1
    }
    
    log_info "Logged in successfully"
}

# Create edge router policies
create_router_policies() {
    log_info "Step 3: Creating router policies..."
    
    # Edge router policy - all identities can use all routers
    ziti_cli edge create edge-router-policy all-routers \
        --identity-roles '#all' \
        --edge-router-roles '#all' 2>/dev/null || log_warn "Edge router policy may exist"
    
    # Service edge router policy - all services available on all routers
    ziti_cli edge create service-edge-router-policy all-services-all-routers \
        --service-roles '#all' \
        --edge-router-roles '#all' 2>/dev/null || log_warn "Service edge router policy may exist"
    
    log_info "Router policies created"
}

# Create services (Dark Services - no inbound ports)
create_services() {
    log_info "Step 4: Creating dark services..."
    
    # App1 Service Configuration
    log_info "Creating app1 service (Branch A - 10.201.0.100)..."
    
    # Create app1 service
    ziti_cli edge create config app1-intercept-config intercept.v1 \
        '{"protocols":["tcp"],"addresses":["app1.ziti"],"portRanges":[{"low":80,"high":80}]}' 2>/dev/null || true
    
    ziti_cli edge create config app1-host-config host.v1 \
        '{"protocol":"tcp","address":"10.201.0.100","port":80}' 2>/dev/null || true
    
    ziti_cli edge create service app1 \
        --configs app1-intercept-config,app1-host-config \
        --role-attributes app1-service 2>/dev/null || log_warn "app1 service may exist"
    
    # App2 Service Configuration
    log_info "Creating app2 service (Branch B - 10.202.0.100)..."
    
    ziti_cli edge create config app2-intercept-config intercept.v1 \
        '{"protocols":["tcp"],"addresses":["app2.ziti"],"portRanges":[{"low":80,"high":80}]}' 2>/dev/null || true
    
    ziti_cli edge create config app2-host-config host.v1 \
        '{"protocol":"tcp","address":"10.202.0.100","port":80}' 2>/dev/null || true
    
    ziti_cli edge create service app2 \
        --configs app2-intercept-config,app2-host-config \
        --role-attributes app2-service 2>/dev/null || log_warn "app2 service may exist"
    
    log_info "Dark services created (no inbound ports needed!)"
}

# Create service policies
create_service_policies() {
    log_info "Step 5: Creating service policies..."
    
    # Bind policies (which identities can host services)
    # Router A hosts app1
    ziti_cli edge create service-policy app1-bind Bind \
        --service-roles '@app1' \
        --identity-roles '#router-a' 2>/dev/null || log_warn "app1-bind policy may exist"
    
    # Router B hosts app2
    ziti_cli edge create service-policy app2-bind Bind \
        --service-roles '@app2' \
        --identity-roles '#router-b' 2>/dev/null || log_warn "app2-bind policy may exist"
    
    # Dial policies (which identities can access services)
    # Users can dial app1
    ziti_cli edge create service-policy app1-dial Dial \
        --service-roles '@app1' \
        --identity-roles '#users' 2>/dev/null || log_warn "app1-dial policy may exist"
    
    # Users can dial app2
    ziti_cli edge create service-policy app2-dial Dial \
        --service-roles '@app2' \
        --identity-roles '#users' 2>/dev/null || log_warn "app2-dial policy may exist"
    
    log_info "Service policies created"
}

# Create test user identity
create_test_user() {
    log_info "Step 6: Creating test user identity..."
    
    # Create test user with enrollment token
    ENROLLMENT_OUTPUT=$(ziti_cli edge create identity user testuser \
        --role-attributes users \
        -o /persistent/identities/testuser.jwt 2>&1) || log_warn "testuser may exist"
    
    # Copy enrollment token out of container
    docker cp ziti-controller:/persistent/identities/testuser.jwt \
        "$PROJECT_DIR/docker/openziti-identities/testuser.jwt" 2>/dev/null || true
    
    log_info "Test user 'testuser' created"
    log_info "JWT saved to: docker/openziti-identities/testuser.jwt"
}

# Create admin identity for testing
create_admin_identity() {
    log_info "Step 7: Creating admin identity..."
    
    ziti_cli edge create identity user admin-test \
        --role-attributes users,admins \
        -o /persistent/identities/admin-test.jwt 2>/dev/null || log_warn "admin-test may exist"
    
    docker cp ziti-controller:/persistent/identities/admin-test.jwt \
        "$PROJECT_DIR/docker/openziti-identities/admin-test.jwt" 2>/dev/null || true
    
    log_info "Admin identity created"
}

# Create router identities
create_router_identities() {
    log_info "Step 8: Creating router identities..."
    
    # PoP Router
    ziti_cli edge create edge-router router-pop \
        --role-attributes pop-router \
        -o /persistent/routers/router-pop.jwt 2>/dev/null || log_warn "router-pop may exist"
    
    # Branch A Router
    ziti_cli edge create edge-router router-a \
        --role-attributes router-a \
        -o /persistent/routers/router-a.jwt 2>/dev/null || log_warn "router-a may exist"
    
    # Branch B Router
    ziti_cli edge create edge-router router-b \
        --role-attributes router-b \
        -o /persistent/routers/router-b.jwt 2>/dev/null || log_warn "router-b may exist"
    
    log_info "Router identities created"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  ZTNA Setup Complete${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "Services Created:"
    echo "  - app1.ziti → 10.201.0.100:80 (Branch A)"
    echo "  - app2.ziti → 10.202.0.100:80 (Branch B)"
    echo ""
    echo "Identities Created:"
    echo "  - testuser (JWT: docker/openziti-identities/testuser.jwt)"
    echo "  - admin-test (JWT: docker/openziti-identities/admin-test.jwt)"
    echo ""
    echo "Routers:"
    echo "  - router-pop (Security PoP)"
    echo "  - router-a (Branch A - hosts app1)"
    echo "  - router-b (Branch B - hosts app2)"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "  1. Enroll test identity: ./scripts/ziti-enroll-user.sh"
    echo "  2. Install Ziti Desktop Edge: https://openziti.io/docs/downloads"
    echo "  3. Test access: curl http://app1.ziti"
    echo ""
    echo "Documentation: docs/ZTNA_GUIDE.md"
}

# Main
main() {
    print_header
    
    mkdir -p "$PROJECT_DIR/docker/openziti-identities"
    
    wait_for_controller || exit 1
    login_controller || exit 1
    create_router_policies
    create_router_identities
    create_services
    create_service_policies
    create_test_user
    create_admin_identity
    
    print_summary
}

main "$@"
