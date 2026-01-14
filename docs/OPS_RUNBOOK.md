# OpenSASE-Lab Operations Runbook

This runbook provides step-by-step procedures for common operational tasks.

---

## Table of Contents

1. [Initial Setup](#initial-setup)
2. [Daily Operations](#daily-operations)
3. [Troubleshooting](#troubleshooting)
4. [Maintenance](#maintenance)
5. [Emergency Procedures](#emergency-procedures)

---

## Initial Setup

### Prerequisites

- Docker Engine 24.0+ with Compose V2
- 16GB RAM (8GB for lite mode)
- 20GB free disk space
- Ports 3000, 3001, 5601, 8080, 8443 available

### First-Time Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/opensase-lab.git
cd opensase-lab

# 2. Create environment file
cp .env.example .env

# 3. Edit secrets (REQUIRED for security)
nano .env  # Change all 'changeme_*' values

# 4. Start the lab
make up

# 5. Wait for services to be healthy (2-5 minutes)
make status

# 6. Run smoke tests
make smoke-test
```

### FlexiWAN Activation

FlexiWAN requires a free account for initial activation:

1. Register at https://flexiwan.com/register
2. Create an organization
3. Note your organization token
4. Update `.env` with your credentials
5. Restart FlexiWAN: `make restart-flexiwan-controller`

### Accessing Services

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Unified Portal | http://localhost:8080 | Keycloak SSO |
| FlexiWAN | http://localhost:3000 | See .env |
| Grafana | http://localhost:3001 | admin / (see .env) |
| Wazuh | http://localhost:5601 | wazuh-wui / (see .env) |
| Keycloak | http://localhost:8443 | admin / (see .env) |

---

## Daily Operations

### Health Check

```bash
# Quick status
make status

# Detailed health check
./scripts/health-check.sh
```

### Viewing Logs

```bash
# All services
make logs

# Specific service
make logs-security-pop
make logs-wazuh-manager

# Follow with grep
docker compose logs -f security-pop 2>&1 | grep -i alert
```

### Checking Security Alerts

**Via Wazuh Dashboard:**
1. Open http://localhost:5601
2. Navigate to Security Events
3. Filter by severity (Critical, High)

**Via API:**
```bash
curl -k -u wazuh-wui:$WAZUH_API_PASSWORD \
  https://localhost:55000/security/alerts?limit=10
```

**Via Portal:**
- Dashboard shows alert summary on main page

### Managing ZTNA Access

**List enrolled identities:**
```bash
docker compose exec ziti-controller ziti edge list identities
```

**Create new identity:**
```bash
./scripts/ziti-create-identity.sh username@corp
```

**Revoke identity:**
```bash
docker compose exec ziti-controller ziti edge delete identity "username@corp"
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs for the failing service
docker compose logs <service-name>

# Common issues:
# - Port conflict: Check if ports are in use
# - Memory: Verify available RAM with `free -h`
# - Volumes: Check disk space with `df -h`
```

### SD-WAN Tunnel Down

```bash
# 1. Check edge status in FlexiWAN UI
# 2. Verify WireGuard interface
docker compose exec branch-a wg show

# 3. Check connectivity to controller
docker compose exec branch-a ping flexiwan-controller

# 4. Restart edge
make restart-branch-a
```

### ZTNA Access Denied

```bash
# 1. Check identity enrollment
docker compose exec ziti-controller ziti edge list identities

# 2. Verify service policy
docker compose exec ziti-controller ziti edge list service-policies

# 3. Check router status
docker compose exec ziti-controller ziti edge list edge-routers

# 4. View session errors
docker compose logs ziti-router-pop | grep -i error
```

### Suricata Not Blocking

```bash
# 1. Verify IPS mode
docker compose exec security-pop suricatasc -c "iface-stat"

# 2. Check rule loading
docker compose exec security-pop suricatasc -c "ruleset-stats"

# 3. Test with known bad signature
docker compose exec branch-a curl http://testmynids.org/uid/index.html

# 4. Check alerts
docker compose exec security-pop tail /var/log/suricata/fast.log
```

### Wazuh Not Receiving Logs

```bash
# 1. Check agent status
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l

# 2. Verify Filebeat
docker compose exec security-pop filebeat test output

# 3. Check indexer health
curl -k -u admin:$INDEXER_PASSWORD https://localhost:9200/_cluster/health

# 4. Restart log pipeline
make restart-wazuh-manager
```

---

## Maintenance

### Regular Updates

```bash
# Pull latest images
docker compose pull

# Rebuild custom images
docker compose build --no-cache

# Restart with new images
make down && make up
```

### Backup Procedures

```bash
# Backup all persistent data
./scripts/backup.sh

# Backups stored in ./backups/ with timestamp
# Includes: MongoDB, Keycloak DB, Wazuh Indexer, Ziti PKI
```

### Log Rotation

Logs are automatically rotated via Docker's json-file driver:
- Max size: 100MB per container
- Max files: 3

To manually clean logs:
```bash
# Truncate all container logs (safe)
docker compose down
sudo sh -c 'truncate -s 0 /var/lib/docker/containers/*/*-json.log'
docker compose up -d
```

### SSL Certificate Renewal

Ziti PKI certificates are valid for 1 year. To renew:

```bash
# 1. Stop Ziti services
docker compose stop ziti-controller ziti-router-pop ziti-router-a ziti-router-b

# 2. Regenerate PKI
./scripts/ziti-pki-renew.sh

# 3. Restart services
docker compose up -d ziti-controller ziti-router-pop ziti-router-a ziti-router-b

# 4. Re-enroll all identities
./scripts/ziti-reenroll-all.sh
```

---

## Emergency Procedures

### Isolate Compromised Branch

```bash
# 1. Disable FlexiWAN edge (stops all traffic)
docker compose exec flexiwan-controller \
  curl -X POST http://localhost:3000/api/devices/branch-a/disable

# 2. Revoke Ziti identities for that branch
docker compose exec ziti-controller ziti edge delete identity "branch-a-*"

# 3. Block at firewall level
docker compose exec security-pop nft add rule inet filter forward \
  ip saddr 10.201.0.0/24 drop

# 4. Collect logs for forensics
./scripts/collect-forensics.sh branch-a
```

### Emergency Shutdown

```bash
# Graceful shutdown (preferred)
make down

# Force shutdown (if stuck)
docker compose kill
docker compose down -v --remove-orphans
```

### Restore from Backup

```bash
# 1. Stop all services
make down

# 2. List available backups
ls -la ./backups/

# 3. Restore specific backup
./scripts/restore.sh ./backups/opensase-lab-2026-01-13.tar.gz

# 4. Start services
make up

# 5. Verify restoration
make smoke-test
```

### Rollback Configuration Change

```bash
# Docker Compose configs are in git - use git to rollback
git diff HEAD~1  # Review changes
git checkout HEAD~1 -- docker-compose.yml  # Rollback specific file
make down && make up

# For Ziti policies
docker compose exec ziti-controller ziti edge list service-policies
# Manually recreate previous policy state
```

---

## Runbook Maintenance

- **Review Frequency:** Monthly
- **Owner:** Operations Team
- **Last Updated:** 2026-01-13
- **Version:** 1.0
