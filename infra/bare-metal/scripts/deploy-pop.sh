#!/bin/bash
# OpenSASE Bare Metal Orchestrator (OBMO)
# Single-Command PoP Deployment - DEDICATED SERVERS ONLY
#
# Usage: ./deploy-pop.sh <provider> <pop-name> <region> [options]
#
# Providers: equinix, ovh, hetzner, scaleway, leaseweb, phoenixnap
#
# Examples:
#   ./deploy-pop.sh equinix pop-nyc ny --plan n3.xlarge.x86 --bgp
#   ./deploy-pop.sh hetzner pop-fra fsn1 --type AX161
#   ./deploy-pop.sh scaleway pop-ams nl-ams-1 --offer EM-A315X-SSD

set -euo pipefail

# ===========================================
# Configuration
# ===========================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBMO_DIR="${SCRIPT_DIR}/.."
TF_DIR="${OBMO_DIR}/terraform"
ANSIBLE_DIR="${OBMO_DIR}/ansible"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Timer
START_TIME=$(date +%s)

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ===========================================
# Arguments
# ===========================================

PROVIDER="${1:-}"
POP_NAME="${2:-}"
REGION="${3:-}"
shift 3 || true

# Default options
PLAN=""
INSTANCE_COUNT=2
ENABLE_BGP=false
DESTROY=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --plan|--type|--offer)
            PLAN="$2"
            shift 2
            ;;
        --count)
            INSTANCE_COUNT="$2"
            shift 2
            ;;
        --bgp)
            ENABLE_BGP=true
            shift
            ;;
        --destroy)
            DESTROY=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$PROVIDER" ] || [ -z "$POP_NAME" ] || [ -z "$REGION" ]; then
    echo "OBMO - OpenSASE Bare Metal Orchestrator"
    echo ""
    echo "Usage: $0 <provider> <pop-name> <region> [options]"
    echo ""
    echo "Providers (BARE METAL ONLY - NO CLOUD VMs):"
    echo "  equinix    - Equinix Metal (100 Gbps capable)"
    echo "  ovh        - OVH Dedicated Servers"
    echo "  hetzner    - Hetzner AX-Series"
    echo "  scaleway   - Scaleway Elastic Metal"
    echo "  leaseweb   - Leaseweb Bare Metal"
    echo "  phoenixnap - PhoenixNAP BMC"
    echo ""
    echo "Options:"
    echo "  --plan <plan>    Server plan (provider-specific)"
    echo "  --count <n>      Number of servers (default: 2)"
    echo "  --bgp            Enable BGP for anycast"
    echo "  --destroy        Destroy existing PoP"
    echo ""
    echo "Examples:"
    echo "  $0 equinix pop-nyc ny --plan n3.xlarge.x86 --bgp"
    echo "  $0 hetzner pop-fra fsn1 --plan AX161"
    echo "  $0 scaleway pop-ams nl-ams-1 --plan EM-A315X-SSD"
    exit 1
fi

# ===========================================
# Validate Provider
# ===========================================

VALID_PROVIDERS=("equinix" "ovh" "hetzner" "scaleway" "leaseweb" "phoenixnap")
if [[ ! " ${VALID_PROVIDERS[@]} " =~ " ${PROVIDER} " ]]; then
    log_error "Invalid provider: $PROVIDER"
    log_error "Must be one of: ${VALID_PROVIDERS[*]}"
    exit 1
fi

# ===========================================
# Default Plans by Provider
# ===========================================

if [ -z "$PLAN" ]; then
    case $PROVIDER in
        equinix)   PLAN="n3.xlarge.x86" ;;   # 100 Gbps Mellanox CX6
        ovh)       PLAN="ADVANCE-6" ;;        # 64 cores, 25 Gbps
        hetzner)   PLAN="AX161" ;;            # 64 cores, 20 Gbps
        scaleway)  PLAN="EM-A315X-SSD" ;;     # 64 cores, 45 Gbps
        leaseweb)  PLAN="BARE_METAL_XL" ;;    # 100 Gbps
        phoenixnap) PLAN="d2.c3.xlarge" ;;    # 100 Gbps Mellanox
    esac
    log_info "Using default plan for $PROVIDER: $PLAN"
fi

# ===========================================
# Environment Variable Checks
# ===========================================

log_step "[1/8] Checking environment variables..."

check_env() {
    local var_name=$1
    if [ -z "${!var_name:-}" ]; then
        log_error "Required: export $var_name=..."
        exit 1
    fi
}

case $PROVIDER in
    equinix)
        check_env "METAL_AUTH_TOKEN"
        check_env "EQUINIX_PROJECT_ID"
        ;;
    ovh)
        check_env "OVH_APPLICATION_KEY"
        check_env "OVH_APPLICATION_SECRET"
        check_env "OVH_CONSUMER_KEY"
        ;;
    hetzner)
        check_env "HETZNER_ROBOT_USER"
        check_env "HETZNER_ROBOT_PASSWORD"
        ;;
    scaleway)
        check_env "SCW_ACCESS_KEY"
        check_env "SCW_SECRET_KEY"
        check_env "SCW_DEFAULT_PROJECT_ID"
        ;;
    leaseweb)
        check_env "LEASEWEB_API_KEY"
        ;;
    phoenixnap)
        check_env "PHOENIXNAP_CLIENT_ID"
        check_env "PHOENIXNAP_CLIENT_SECRET"
        ;;
esac

check_env "FLEXIWAN_TOKEN"
check_env "SSH_PUBLIC_KEY"

log_info "Environment variables OK"

# ===========================================
# Destroy Mode
# ===========================================

if [ "$DESTROY" == true ]; then
    log_warn "Destroying PoP: $POP_NAME on $PROVIDER"
    
    cd "${TF_DIR}/providers/${PROVIDER}"
    
    terraform destroy \
        -var="pop_name=${POP_NAME}" \
        -var="activation_key=${FLEXIWAN_TOKEN}" \
        -auto-approve
    
    log_info "PoP $POP_NAME destroyed"
    exit 0
fi

# ===========================================
# Banner
# ===========================================

echo ""
echo "================================================================"
echo -e "  ${CYAN}OpenSASE Bare Metal Orchestrator (OBMO)${NC}"
echo "  100+ Gbps Dedicated Server Deployment"
echo "================================================================"
echo ""
echo "  Provider:  $PROVIDER (BARE METAL)"
echo "  PoP Name:  $POP_NAME"
echo "  Region:    $REGION"
echo "  Plan:      $PLAN"
echo "  Instances: $INSTANCE_COUNT"
echo "  BGP:       $ENABLE_BGP"
echo ""
echo "================================================================"
echo ""

# ===========================================
# Terraform Init
# ===========================================

log_step "[2/8] Initializing Terraform..."

cd "${TF_DIR}/providers/${PROVIDER}"

terraform init -upgrade \
    -backend-config="key=obmo/${PROVIDER}/${POP_NAME}/terraform.tfstate"

# ===========================================
# Terraform Plan
# ===========================================

log_step "[3/8] Planning infrastructure..."

# Build var args based on provider
VAR_ARGS=(
    -var="pop_name=${POP_NAME}"
    -var="instance_count=${INSTANCE_COUNT}"
    -var="activation_key=${FLEXIWAN_TOKEN}"
    -var="ssh_public_key=${SSH_PUBLIC_KEY}"
)

case $PROVIDER in
    equinix)
        VAR_ARGS+=(
            -var="project_id=${EQUINIX_PROJECT_ID}"
            -var="metro=${REGION}"
            -var="plan=${PLAN}"
            -var="enable_bgp=${ENABLE_BGP}"
        )
        ;;
    ovh)
        VAR_ARGS+=(
            -var="datacenter=${REGION}"
            -var="plan=${PLAN}"
        )
        ;;
    hetzner)
        VAR_ARGS+=(
            -var="datacenter=${REGION}"
            -var="server_type=${PLAN}"
            -var="robot_user=${HETZNER_ROBOT_USER}"
            -var="robot_password=${HETZNER_ROBOT_PASSWORD}"
        )
        ;;
    scaleway)
        VAR_ARGS+=(
            -var="zone=${REGION}"
            -var="offer=${PLAN}"
        )
        ;;
esac

terraform plan "${VAR_ARGS[@]}" -out=tfplan

# ===========================================
# Terraform Apply
# ===========================================

log_step "[4/8] Provisioning bare metal servers..."

terraform apply -auto-approve tfplan

# ===========================================
# Get Outputs
# ===========================================

log_step "[5/8] Retrieving server information..."

PUBLIC_IPS=$(terraform output -json public_ips 2>/dev/null | jq -r '.[]' || echo "")
PRIVATE_IPS=$(terraform output -json private_ips 2>/dev/null | jq -r '.[]' || echo "")

if [ -z "$PUBLIC_IPS" ]; then
    log_warn "No IPs returned yet - server may still be provisioning"
    log_info "Check provider dashboard for status"
else
    log_info "Servers provisioned:"
    for ip in $PUBLIC_IPS; do
        echo "  - $ip"
    done
fi

# ===========================================
# Wait for SSH
# ===========================================

log_step "[6/8] Waiting for SSH access..."

if [ -n "$PUBLIC_IPS" ]; then
    for ip in $PUBLIC_IPS; do
        log_info "Waiting for SSH on $ip..."
        for i in {1..60}; do
            if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                -i ~/.ssh/opensase root@"$ip" "echo ready" 2>/dev/null; then
                break
            fi
            sleep 10
        done
    done
fi

# ===========================================
# Run Ansible Configuration
# ===========================================

log_step "[7/8] Running Ansible configuration..."

cd "${ANSIBLE_DIR}"

if [ -f "inventory/${PROVIDER}-${POP_NAME}.yml" ]; then
    ansible-playbook \
        -i "inventory/${PROVIDER}-${POP_NAME}.yml" \
        playbooks/bare-metal-setup.yml \
        --extra-vars "pop_name=${POP_NAME}" \
        --extra-vars "provider=${PROVIDER}" \
        --extra-vars "activation_key=${FLEXIWAN_TOKEN}"
fi

# ===========================================
# Verify Deployment
# ===========================================

log_step "[8/8] Verifying deployment..."

if [ -n "$PUBLIC_IPS" ]; then
    for ip in $PUBLIC_IPS; do
        log_info "Checking health on $ip..."
        curl -sf "http://${ip}:8080/health" | jq . || log_warn "Health check pending"
    done
fi

# ===========================================
# Completion
# ===========================================

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo ""
echo "================================================================"
echo -e "  ${GREEN}OBMO Deployment Complete!${NC}"
echo "================================================================"
echo ""
echo "  Provider:   $PROVIDER (BARE METAL)"
echo "  PoP Name:   $POP_NAME"
echo "  Region:     $REGION"
echo "  Plan:       $PLAN"
echo "  Duration:   ${MINUTES}m ${SECONDS}s"
echo ""

if [ -n "$PUBLIC_IPS" ]; then
    echo "  Servers:"
    for ip in $PUBLIC_IPS; do
        echo "    - $ip"
    done
    echo ""
    echo "  Access:"
    for ip in $PUBLIC_IPS; do
        echo "    ssh root@$ip"
    done
fi

echo ""
echo "================================================================"
echo ""

# Target check
if [ $DURATION -lt 900 ]; then
    log_info "✅ Deployed in under 15 minutes! (${MINUTES}m ${SECONDS}s)"
else
    log_warn "⚠️ Deployment took ${MINUTES}m ${SECONDS}s (target: <15 min)"
fi
