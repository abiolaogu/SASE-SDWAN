# Administrator User Manual -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Getting Started

### 1.1 Prerequisites
- Docker Engine 24.0+ with Compose V2
- 16 GB RAM (8 GB for lite mode)
- 20 GB free disk space
- Ports available: 3000, 3001, 5601, 8080, 8443

### 1.2 Initial Setup
```bash
git clone https://github.com/opensase/opensase-lab.git
cd opensase-lab
cp .env.example .env
nano .env  # Change all 'changeme_*' values
make up
make status
make smoke-test
```

### 1.3 Service Access
| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Unified Portal | http://localhost:8080 | admin / admin123 |
| FlexiWAN | http://localhost:3000 | See .env |
| Grafana | http://localhost:3001 | admin / (see GF_SECURITY_ADMIN_PASSWORD) |
| Wazuh Dashboard | http://localhost:5601 | wazuh-wui / (see WAZUH_API_PASSWORD) |
| Keycloak Admin | http://localhost:8443 | admin / (see KEYCLOAK_ADMIN_PASSWORD) |

## 2. Site Management

### 2.1 Adding a New Site
1. Navigate to Portal > Sites page
2. Click "Add Site" button
3. Fill in: site name, location, timezone
4. System generates bootstrap token for edge device
5. Power on edge appliance with token

### 2.2 Monitoring Sites
The Dashboard page shows all sites with status indicators:
- **Active** (green): Site connected, tunnels healthy
- **Degraded** (yellow): High latency or partial tunnel failure
- **Offline** (red): No heartbeat from edge device

From `opensase-portal/src/pages/Dashboard.tsx`, the device table shows: Device Name, Type (Branch/Hub), Status, Active Tunnels, Last Seen.

### 2.3 Removing a Site
1. Navigate to Sites page
2. Select site to remove
3. Confirm deletion (this will tear down all tunnels from that site)

## 3. Tunnel Configuration

### 3.1 Viewing Tunnel Status
Navigate to Portal > Tunnels page (`opensase-portal/src/pages/Tunnels.tsx`). Each tunnel shows:
- Tunnel ID, name, type (WireGuard)
- Status (connected/disconnected)
- Local and remote IP addresses
- Latency (ms), jitter (ms), packet loss (%)
- RX/TX bytes, uptime

From `api/src/models.rs`, `TunnelStats` includes: `latency_ms`, `jitter_ms`, `packet_loss_percent`, `rx_bytes`, `tx_bytes`, `uptime_seconds`.

### 3.2 WireGuard Tunnel Parameters
Default tunnel configuration from `docker-compose.yml`:
- Encryption: ChaCha20-Poly1305
- Key exchange: X25519
- MTU: 1420
- Keepalive interval: 25 seconds

### 3.3 Adding a Branch
```bash
./scripts/add-branch.sh <branch-name> <branch-id>
# Example:
./scripts/add-branch.sh branch-d 4
```

## 4. Policy Management

### 4.1 Creating Access Policies
Navigate to Portal > Policies page (`opensase-portal/src/pages/Policies.tsx`):
1. Click "Create Policy"
2. Set name, description, priority (lower number = higher priority)
3. Add conditions: source IP, destination, user group, time window, application
4. Select action: Allow, Block, Isolate, or Log
5. Enable/disable the policy
6. Save and deploy

### 4.2 UPO Intent Policies (Advanced)
For complex policies, use the Unified Policy Orchestrator (`components/upo/`):
```yaml
# components/upo/sample_policies/corporate-access.yaml
name: Corporate Access Policy
version: "1.0"
users:
  - name: engineering
    type: group
apps:
  - name: gitlab
    address: 10.201.0.50
    port: 443
    segment: corporate
access_rules:
  - name: allow-engineering-gitlab
    users: [engineering]
    apps: [gitlab]
    action: allow
    priority: 10
```

### 4.3 Policy Actions
From `api/src/models.rs`:
- **Allow**: Permit traffic (default if no rule matches)
- **Block**: Drop traffic, return RST or block page
- **Isolate**: Send to Remote Browser Isolation
- **Log**: Allow but generate audit log entry

## 5. Security Monitoring

### 5.1 Viewing Security Alerts
Navigate to Portal > Security page (`opensase-portal/src/pages/Security.tsx`). Alerts include:
- Severity: Critical, High, Medium, Low
- Message: description of the threat
- Source: which site/device generated the alert
- Timestamp

### 5.2 IPS/IDS Management
Suricata IPS runs on the Security PoP container. View IPS status:
```bash
make security-pop-test
docker exec security-pop suricatasc -c "iface-stat"
```

### 5.3 SIEM Dashboard
Access Wazuh Dashboard at http://localhost:5601 for:
- Security alert timeline
- Suricata alert correlation
- File integrity monitoring
- Vulnerability detection

### 5.4 Generating Test Alerts
```bash
make generate-alerts
make siem-test
```

## 6. Identity and Access Management

### 6.1 Keycloak Administration
Access Keycloak Admin at http://localhost:8443.

Realm: `opensase-lab`
- Default users: admin (Full access), operator (Manage), viewer (Read-only)
- Clients: `portal-app`, `grafana`
- Roles: `admin`, `operator`, `viewer`

### 6.2 Adding Users
1. Log into Keycloak Admin Console
2. Select realm `opensase-lab`
3. Navigate to Users > Add User
4. Set username, email, first/last name
5. Assign roles under Role Mappings

## 7. Observability

### 7.1 Grafana Dashboards
Access Grafana at http://localhost:3001. Pre-configured dashboards:
- SD-WAN Overview: tunnel health, bandwidth utilization
- Security PoP: IPS alerts, DNS queries blocked
- ZTNA Sessions: active sessions, policy decisions
- System Health: CPU, memory, disk per container

### 7.2 Prometheus Queries
Access Prometheus at http://localhost:9090. Key metrics:
- `portal_sites_online`: Number of online sites
- `portal_ztna_sessions`: Active ZTNA sessions
- `portal_alerts_critical`: Critical alerts count
- `portal_policies_active`: Active policies count

## 8. Makefile Commands Reference

```bash
make up              # Start all services (16 GB RAM)
make lite            # Start in lite mode (8 GB RAM)
make down            # Stop all services
make status          # Show service status
make logs            # Tail all logs
make logs-<service>  # Tail specific service logs
make smoke-test      # Run automated validation
make demo            # Interactive walkthrough
make clean           # Remove all data (with confirmation)

# Component-specific:
make up-sdwan        # SD-WAN only
make up-security     # Security PoP only
make up-ztna         # OpenZiti only
make up-siem         # Wazuh only
make up-portal       # Portal + Keycloak
make up-observability # Prometheus + Grafana

# SD-WAN operations:
make sdwan-bootstrap # Initialize FlexiWAN
make sdwan-test      # Test overlay routing
make ztna-bootstrap  # Initialize OpenZiti
make ztna-test       # Test ZTNA services
```

## 9. Troubleshooting

### 9.1 Service Not Starting
```bash
make status                    # Check container status
docker compose logs <service>  # Check specific service logs
```

### 9.2 Tunnel Not Establishing
1. Check FlexiWAN controller is healthy: `curl http://localhost:3000/api/health`
2. Check edge device logs: `docker compose logs branch-a`
3. Verify WireGuard keys in edge config: `docker exec branch-a cat /etc/flexiwan/token`

### 9.3 Wazuh Agent Not Connecting
1. Check Wazuh manager status: `docker exec wazuh-manager /var/ossec/bin/wazuh-control status`
2. Verify registration port: `nc -z localhost 1515`
3. Check agent logs in branch containers

### 9.4 Portal API Errors
1. Check backend health: `curl http://localhost:8000/api/health`
2. Check Keycloak is running: `curl http://localhost:8443/health/ready`
3. Verify OIDC configuration in `.env`

## 10. Backup and Recovery

### 10.1 Data Volumes
Persistent data stored in Docker volumes:
- `flexiwan-mongo-data`: SD-WAN configuration
- `keycloak-db-data`: Identity data
- `wazuh-indexer-data`: SIEM indexes
- `wazuh-manager-data`: SIEM rules and config
- `prometheus-data`: Metrics history
- `grafana-data`: Dashboard configs
- `ziti-controller-data`: ZTNA PKI and policies

### 10.2 Backup Procedure
```bash
docker compose stop
docker run --rm -v flexiwan-mongo-data:/data -v $(pwd)/backups:/backup alpine tar czf /backup/mongo.tar.gz /data
docker run --rm -v keycloak-db-data:/data -v $(pwd)/backups:/backup alpine tar czf /backup/keycloak.tar.gz /data
docker compose start
```

### 10.3 Full Reset
```bash
make clean  # WARNING: Destroys all data
```
