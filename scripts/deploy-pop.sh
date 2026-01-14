#!/bin/bash
# OpenSASE PoP Deployment Script
# One-command deployment from bare metal to fully operational
#
# Usage: ./scripts/deploy-pop.sh <pop_name> [provider] [environment]
# Example: ./scripts/deploy-pop.sh nyc1 equinix production

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ANSIBLE_DIR="${PROJECT_ROOT}/infra/ansible"
TERRAFORM_DIR="${PROJECT_ROOT}/infra/terraform"

# Arguments
POP_NAME=${1:-}
PROVIDER=${2:-equinix}
ENVIRONMENT=${3:-production}

# Environment variables (should be set)
OPENSASE_CONTROLLER_URL=${OPENSASE_CONTROLLER_URL:-"https://api.opensase.io"}
OPENSASE_ACTIVATION_KEY=${OPENSASE_ACTIVATION_KEY:-""}
SSH_KEY_PATH=${SSH_KEY_PATH:-"$HOME/.ssh/id_rsa"}

usage() {
    echo "Usage: $0 <pop_name> [provider] [environment]"
    echo ""
    echo "Arguments:"
    echo "  pop_name     Name of the PoP (e.g., nyc1, fra1, sgp1)"
    echo "  provider     Infrastructure provider (equinix, vultr, packet) [default: equinix]"
    echo "  environment  Deployment environment (production, staging) [default: production]"
    echo ""
    echo "Environment Variables:"
    echo "  OPENSASE_CONTROLLER_URL   API URL for registration"
    echo "  OPENSASE_ACTIVATION_KEY   Activation key from portal"
    echo "  SSH_KEY_PATH              Path to SSH private key"
    echo ""
    echo "Examples:"
    echo "  $0 nyc1 equinix production"
    echo "  $0 fra1 vultr staging"
    exit 1
}

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Validate arguments
if [[ -z "$POP_NAME" ]]; then
    usage
fi

# Start deployment
echo ""
echo "==========================================="
echo "  OpenSASE PoP Deployment"
echo "==========================================="
echo "  PoP Name:     ${POP_NAME}"
echo "  Provider:     ${PROVIDER}"
echo "  Environment:  ${ENVIRONMENT}"
echo "  Controller:   ${OPENSASE_CONTROLLER_URL}"
echo "==========================================="
echo ""

DEPLOYMENT_START=$(date +%s)
DEPLOYMENT_ID=$(date +%Y%m%d%H%M%S)

# Step 1: Provision Infrastructure (Terraform)
log "Step 1/5: Provisioning infrastructure with Terraform..."

cd "${TERRAFORM_DIR}/deployments/${ENVIRONMENT}"

if [[ ! -f "main.tf" ]]; then
    warn "Terraform configuration not found, skipping provisioning..."
    echo "Please provide the server IP manually:"
    read -p "Primary IP: " PRIMARY_IP
else
    terraform init -input=false

    terraform apply -auto-approve \
        -var="pop_name=${POP_NAME}" \
        -var="provider=${PROVIDER}" \
        -target="module.pop_${POP_NAME}" || error "Terraform apply failed"

    # Get server IPs
    PRIMARY_IP=$(terraform output -raw "pop_${POP_NAME}_primary_ip" 2>/dev/null || echo "")
    
    if [[ -z "$PRIMARY_IP" ]]; then
        error "Failed to get server IP from Terraform"
    fi
fi

success "Infrastructure provisioned: ${PRIMARY_IP}"

# Step 2: Wait for server to be ready
log "Step 2/5: Waiting for server to be ready..."

MAX_WAIT=300
WAITED=0

until ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i "${SSH_KEY_PATH}" root@${PRIMARY_IP} true 2>/dev/null; do
    if [[ $WAITED -ge $MAX_WAIT ]]; then
        error "Timeout waiting for SSH (${MAX_WAIT}s)"
    fi
    echo -n "."
    sleep 10
    WAITED=$((WAITED + 10))
done

echo ""
success "Server is ready (waited ${WAITED}s)"

# Step 3: Generate dynamic inventory
log "Step 3/5: Generating Ansible inventory..."

mkdir -p "${ANSIBLE_DIR}/inventory/dynamic"

cat > "${ANSIBLE_DIR}/inventory/dynamic/${POP_NAME}.yml" << EOF
all:
  hosts:
    ${POP_NAME}:
      ansible_host: ${PRIMARY_IP}
      ansible_user: root
      ansible_ssh_private_key_file: ${SSH_KEY_PATH}
      pop_name: ${POP_NAME}
      pop_type: core
      controller_url: ${OPENSASE_CONTROLLER_URL}
      activation_key: ${OPENSASE_ACTIVATION_KEY}
      
      # Enable all components
      vpp_enabled: true
      bird_enabled: true
      wireguard_enabled: true
      suricata_enabled: true
      envoy_enabled: true
      flexiwan_enabled: true
      monitoring_enabled: true
EOF

success "Inventory generated: inventory/dynamic/${POP_NAME}.yml"

# Step 4: Run Ansible deployment
log "Step 4/5: Running Ansible deployment..."

cd "${ANSIBLE_DIR}"

# Run deployment playbook
ansible-playbook \
    -i "inventory/dynamic/${POP_NAME}.yml" \
    playbooks/deploy-pop.yml \
    -e "pop_name=${POP_NAME}" \
    -e "environment=${ENVIRONMENT}" \
    -e "deployment_id=${DEPLOYMENT_ID}" \
    --timeout=120 \
    || error "Ansible deployment failed"

success "Ansible deployment complete"

# Step 5: Verify deployment
log "Step 5/5: Verifying deployment..."

ansible-playbook \
    -i "inventory/dynamic/${POP_NAME}.yml" \
    playbooks/deploy-pop.yml \
    --tags validate \
    || warn "Some validations failed"

# Calculate deployment time
DEPLOYMENT_END=$(date +%s)
DEPLOYMENT_DURATION=$((DEPLOYMENT_END - DEPLOYMENT_START))
DEPLOYMENT_MINUTES=$((DEPLOYMENT_DURATION / 60))
DEPLOYMENT_SECONDS=$((DEPLOYMENT_DURATION % 60))

echo ""
echo "==========================================="
echo "  Deployment Complete!"
echo "==========================================="
echo "  PoP Name:      ${POP_NAME}"
echo "  Primary IP:    ${PRIMARY_IP}"
echo "  Duration:      ${DEPLOYMENT_MINUTES}m ${DEPLOYMENT_SECONDS}s"
echo "  Deployment ID: ${DEPLOYMENT_ID}"
echo "==========================================="
echo ""
echo "  Dashboard: https://portal.opensase.io/pops/${POP_NAME}"
echo "  VPP CLI:   ssh root@${PRIMARY_IP} vppctl"
echo "  BIRD CLI:  ssh root@${PRIMARY_IP} birdc"
echo ""
echo "==========================================="

# Save deployment summary
mkdir -p "${PROJECT_ROOT}/logs"
cat > "${PROJECT_ROOT}/logs/deployment-${DEPLOYMENT_ID}.json" << EOF
{
  "deployment_id": "${DEPLOYMENT_ID}",
  "pop_name": "${POP_NAME}",
  "provider": "${PROVIDER}",
  "environment": "${ENVIRONMENT}",
  "primary_ip": "${PRIMARY_IP}",
  "duration_seconds": ${DEPLOYMENT_DURATION},
  "started_at": "$(date -d @${DEPLOYMENT_START} -Iseconds 2>/dev/null || date -r ${DEPLOYMENT_START} +%Y-%m-%dT%H:%M:%S)",
  "completed_at": "$(date -d @${DEPLOYMENT_END} -Iseconds 2>/dev/null || date -r ${DEPLOYMENT_END} +%Y-%m-%dT%H:%M:%S)",
  "status": "success"
}
EOF

log "Deployment log saved: logs/deployment-${DEPLOYMENT_ID}.json"
