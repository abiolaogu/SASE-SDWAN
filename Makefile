# OpenSASE-Lab Makefile
# Fully reproducible SASE security lab

.PHONY: help up down lite smoke-test demo clean logs status

# Default target
help:
	@echo "OpenSASE-Lab - SASE Security Lab"
	@echo ""
	@echo "Usage:"
	@echo "  make up          - Start all services (full profile, requires 16GB RAM)"
	@echo "  make lite        - Start services in lite mode (8GB RAM)"
	@echo "  make down        - Stop all services"
	@echo "  make smoke-test  - Run automated smoke tests"
	@echo "  make demo        - Interactive demo walkthrough"
	@echo "  make status      - Show status of all services"
	@echo "  make logs        - Tail logs from all services"
	@echo "  make clean       - Remove all containers, volumes, and generated configs"
	@echo ""
	@echo "Individual Components:"
	@echo "  make up-sdwan    - Start only SD-WAN components"
	@echo "  make up-security - Start only Security PoP"
	@echo "  make up-ztna     - Start only OpenZiti ZTNA"
	@echo "  make up-siem     - Start only Wazuh SIEM"
	@echo "  make up-portal   - Start only the unified portal"
	@echo ""
	@echo "SD-WAN Operations:"
	@echo "  make sdwan-bootstrap - Initialize FlexiWAN controller and edges"
	@echo "  make sdwan-test      - Test SD-WAN overlay and routing"
	@echo "  make add-branch      - Show add-branch usage"
	@echo ""
	@echo "Custom Components:"
	@echo "  make demo-components - Demo all custom SASE components"
	@echo "  make install-components - Install all Python components"

# ============================================
# Environment Setup
# ============================================
.env:
	@if [ ! -f .env ]; then \
		echo "Creating .env from .env.example..."; \
		cp .env.example .env; \
		echo "WARNING: Using default passwords. Edit .env for production use."; \
	fi

# ============================================
# Full Stack Operations
# ============================================
up: .env
	@echo "Starting OpenSASE-Lab (Full Profile)..."
	@./scripts/generate-configs.sh
	docker compose up -d
	@echo ""
	@echo "Services starting. Run 'make status' to check progress."
	@echo "Run 'make smoke-test' after services are healthy."

lite: .env
	@echo "Starting OpenSASE-Lab (Lite Profile - 8GB RAM)..."
	@./scripts/generate-configs.sh
	docker compose -f docker-compose.yml -f docker-compose.lite.yml up -d
	@echo ""
	@echo "Lite mode: Wazuh indexer replication disabled, reduced resources."

down:
	@echo "Stopping OpenSASE-Lab..."
	docker compose down
	@echo "All services stopped."

# ============================================
# Individual Component Operations
# ============================================
up-sdwan: .env
	docker compose up -d flexiwan-controller flexiwan-mongo branch-a branch-b branch-c

up-security: .env
	docker compose up -d security-pop

up-ztna: .env
	@./scripts/ziti-bootstrap.sh --init-only
	docker compose up -d ziti-controller ziti-router-pop ziti-router-a ziti-router-b app1 app2

up-siem: .env
	docker compose up -d wazuh-manager wazuh-indexer wazuh-dashboard

up-portal: .env
	docker compose up -d portal-backend portal-frontend keycloak keycloak-db

up-observability: .env
	docker compose up -d prometheus grafana

# ============================================
# SD-WAN Operations
# ============================================
sdwan-bootstrap: .env
	@echo "Bootstrapping FlexiWAN controller..."
	@./scripts/flexiwan-bootstrap.sh
	@./scripts/flexiwan-edge-bootstrap.sh

sdwan-test:
	@echo "Testing SD-WAN overlay and routing..."
	@./scripts/test-sdwan.sh

security-pop-test:
	@echo "Testing Security PoP gateway..."
	@./scripts/test-security-pop.sh

ztna-bootstrap:
	@echo "Bootstrapping OpenZiti ZTNA..."
	@./scripts/ziti-bootstrap.sh

ztna-enroll:
	@echo "Enrolling test user..."
	@./scripts/ziti-enroll-user.sh

ztna-test:
	@echo "Testing ZTNA services..."
	@./scripts/test-ztna.sh

generate-alerts:
	@echo "Generating synthetic alerts for demo..."
	@./scripts/generate-alerts.sh

siem-test:
	@echo "Testing SIEM detection..."
	@./scripts/generate-alerts.sh
	@sleep 5
	@docker exec wazuh-manager tail -10 /var/ossec/logs/alerts/alerts.json | jq -r '.rule.description' 2>/dev/null || echo "Check Wazuh dashboard for alerts"

add-branch:
	@echo "Usage: ./scripts/add-branch.sh <branch-name> <branch-id>"
	@echo "Example: ./scripts/add-branch.sh branch-d 4"

# ============================================
# Custom SASE Components
# ============================================
demo-components:
	@echo "Running custom components demo..."
	@./scripts/demo-components.sh

install-components:
	@echo "Installing custom SASE components..."
	pip install -e components/upo
	pip install -e components/qoe-selector
	pip install -e components/casb-lite
	pip install -e components/dlp-lite
	@echo "All components installed."

test-components:
	@echo "Testing custom components..."
	cd components/upo && python -m pytest tests/ -v || true
	@echo "Component tests complete."

# ============================================
# Testing
# ============================================
smoke-test:
	@echo "Running smoke tests..."
	@./scripts/smoke-test.sh

demo:
	@echo "Starting interactive demo..."
	@./scripts/demo.sh

# ============================================
# Utilities
# ============================================
status:
	@echo "OpenSASE-Lab Service Status:"
	@echo "============================"
	@docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

logs:
	docker compose logs -f --tail=100

logs-%:
	docker compose logs -f --tail=100 $*

shell-%:
	docker compose exec $* /bin/sh

# ============================================
# Cleanup
# ============================================
clean:
	@echo "WARNING: This will remove all containers, volumes, and generated configs!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	docker compose down -v --remove-orphans
	rm -rf data/ volumes/
	rm -f docker/openziti-controller/pki/*.pem
	rm -f docker/wazuh/config/wazuh_indexer_ssl_certs/*.pem
	@echo "Cleanup complete."

# ============================================
# Development Helpers
# ============================================
rebuild-%:
	docker compose build --no-cache $*
	docker compose up -d $*

restart-%:
	docker compose restart $*
