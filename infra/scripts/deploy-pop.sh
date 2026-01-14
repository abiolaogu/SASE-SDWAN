#!/bin/bash
# OpenSASE Infrastructure Automation (OSIA)
# Single Command PoP Deployment
#
# Usage: ./deploy-pop.sh <pop-name> <provider> <region> [--destroy]
#
# Examples:
#   ./deploy-pop.sh pop-nyc aws us-east-1
#   ./deploy-pop.sh pop-ldn gcp europe-west2
#   ./deploy-pop.sh pop-fra azure westeurope
#   ./deploy-pop.sh pop-hel hetzner fsn1

set -euo pipefail

# ===========================================
# Configuration
# ===========================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="${SCRIPT_DIR}/.."
TERRAFORM_DIR="${INFRA_DIR}/terraform"
ANSIBLE_DIR="${INFRA_DIR}/ansible"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Timing
START_TIME=$(date +%s)

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# ===========================================
# Arguments
# ===========================================

POP_NAME="${1:-}"
CLOUD_PROVIDER="${2:-}"
REGION="${3:-}"
DESTROY="${4:-}"

if [ -z "$POP_NAME" ] || [ -z "$CLOUD_PROVIDER" ] || [ -z "$REGION" ]; then
    echo "Usage: $0 <pop-name> <provider> <region> [--destroy]"
    echo ""
    echo "Providers: aws, gcp, azure, hetzner"
    echo ""
    echo "Examples:"
    echo "  $0 pop-nyc aws us-east-1"
    echo "  $0 pop-ldn gcp europe-west2"
    echo "  $0 pop-fra azure westeurope"
    echo "  $0 pop-hel hetzner fsn1"
    exit 1
fi

# ===========================================
# Environment Variables Check
# ===========================================

check_env() {
    local var_name=$1
    if [ -z "${!var_name:-}" ]; then
        log_error "Required environment variable $var_name is not set"
        exit 1
    fi
}

log_step "Checking required environment variables..."

case $CLOUD_PROVIDER in
    aws)
        check_env "AWS_ACCESS_KEY_ID"
        check_env "AWS_SECRET_ACCESS_KEY"
        ;;
    gcp)
        check_env "GOOGLE_APPLICATION_CREDENTIALS"
        ;;
    azure)
        check_env "ARM_SUBSCRIPTION_ID"
        check_env "ARM_TENANT_ID"
        check_env "ARM_CLIENT_ID"
        check_env "ARM_CLIENT_SECRET"
        ;;
    hetzner)
        check_env "HCLOUD_TOKEN"
        ;;
    *)
        log_error "Unknown provider: $CLOUD_PROVIDER"
        exit 1
        ;;
esac

check_env "FLEXIWAN_TOKEN"
check_env "SSH_PUBLIC_KEY"

# ===========================================
# Destroy Mode
# ===========================================

if [ "$DESTROY" == "--destroy" ]; then
    log_warn "Destroying PoP: $POP_NAME"
    
    cd "$TERRAFORM_DIR"
    
    terraform destroy \
        -var="pop_name=${POP_NAME}" \
        -var="cloud_provider=${CLOUD_PROVIDER}" \
        -var="region=${REGION}" \
        -var="ssh_public_key=${SSH_PUBLIC_KEY}" \
        -var="flexiwan_token=${FLEXIWAN_TOKEN}" \
        -auto-approve
    
    log_info "PoP $POP_NAME destroyed successfully"
    exit 0
fi

# ===========================================
# Deployment
# ===========================================

echo ""
echo "============================================"
echo -e "  ${CYAN}OpenSASE PoP Deployment${NC}"
echo "============================================"
echo ""
echo "  PoP Name:  $POP_NAME"
echo "  Provider:  $CLOUD_PROVIDER"
echo "  Region:    $REGION"
echo ""
echo "============================================"
echo ""

# ===========================================
# Step 1: Terraform Init
# ===========================================

log_step "[1/5] Initializing Terraform..."

cd "$TERRAFORM_DIR"

terraform init -upgrade \
    -backend-config="key=pops/${POP_NAME}/terraform.tfstate"

# ===========================================
# Step 2: Terraform Plan
# ===========================================

log_step "[2/5] Planning infrastructure..."

terraform plan \
    -var="pop_name=${POP_NAME}" \
    -var="cloud_provider=${CLOUD_PROVIDER}" \
    -var="region=${REGION}" \
    -var="ssh_public_key=${SSH_PUBLIC_KEY}" \
    -var="flexiwan_token=${FLEXIWAN_TOKEN}" \
    -out=tfplan

# ===========================================
# Step 3: Terraform Apply
# ===========================================

log_step "[3/5] Provisioning infrastructure..."

terraform apply -auto-approve tfplan

# Get outputs
INSTANCE_IPS=$(terraform output -json instance_ips | jq -r '.[]')
DNS_ENDPOINT=$(terraform output -raw dns_endpoint)

log_info "Instances provisioned: $INSTANCE_IPS"
log_info "DNS endpoint: $DNS_ENDPOINT"

# ===========================================
# Step 4: Generate Ansible Inventory
# ===========================================

log_step "[4/5] Generating Ansible inventory..."

INVENTORY_FILE="${ANSIBLE_DIR}/inventory/${POP_NAME}.yml"

cat > "$INVENTORY_FILE" << EOF
---
all:
  children:
    pop_nodes:
      hosts:
$(for ip in $INSTANCE_IPS; do
echo "        ${POP_NAME}-$(echo $ip | tr '.' '-'):"
echo "          ansible_host: ${ip}"
done)
      vars:
        ansible_user: ubuntu
        ansible_ssh_private_key_file: ~/.ssh/opensase
        pop_name: ${POP_NAME}
        flexiwan_url: https://manage.opensase.io
        flexiwan_token: ${FLEXIWAN_TOKEN}
        cloud_provider: ${CLOUD_PROVIDER}
        region: ${REGION}
EOF

log_info "Inventory generated: $INVENTORY_FILE"

# ===========================================
# Step 5: Wait for SSH
# ===========================================

log_step "[5/5] Waiting for instances to be ready..."

for ip in $INSTANCE_IPS; do
    log_info "Waiting for SSH on $ip..."
    
    for i in {1..30}; do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            -i ~/.ssh/opensase ubuntu@"$ip" "echo ready" 2>/dev/null; then
            break
        fi
        sleep 10
    done
done

# ===========================================
# Step 6: Run Ansible
# ===========================================

log_step "[6/6] Running Ansible configuration..."

cd "$ANSIBLE_DIR"

ansible-playbook \
    -i "inventory/${POP_NAME}.yml" \
    playbooks/deploy-pop.yml \
    --extra-vars "pop_name=${POP_NAME} flexiwan_token=${FLEXIWAN_TOKEN}"

# ===========================================
# Completion
# ===========================================

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo ""
echo "============================================"
echo -e "  ${GREEN}OpenSASE PoP Deployment Complete!${NC}"
echo "============================================"
echo ""
echo "  PoP Name:    $POP_NAME"
echo "  Provider:    $CLOUD_PROVIDER"
echo "  Region:      $REGION"
echo "  Duration:    ${MINUTES}m ${SECONDS}s"
echo ""
echo "  Instances:"
for ip in $INSTANCE_IPS; do
echo "    - $ip"
done
echo ""
echo "  Endpoints:"
echo "    DNS:       $DNS_ENDPOINT"
echo "    Health:    https://${DNS_ENDPOINT}/health"
echo "    API:       https://api.${DNS_ENDPOINT}"
echo ""
echo "  SSH Access:"
echo "    ssh -i ~/.ssh/opensase ubuntu@${DNS_ENDPOINT}"
echo ""
echo "============================================"
echo ""

# Check if under 15 minutes
if [ $DURATION -lt 900 ]; then
    log_info "✅ Deployment completed in under 15 minutes! ($MINUTES m $SECONDS s)"
else
    log_warn "⚠️ Deployment took longer than 15 minutes ($MINUTES m $SECONDS s)"
fi
