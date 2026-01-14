# OpenSASE Connector Deployment

## Connector Types

| Type | Use Case | Deployment |
|------|----------|------------|
| **Agent** | On-premises apps | Install on internal server |
| **CloudNative** | Cloud apps | API integration |
| **Tunnel** | Network access | WireGuard tunnel |
| **Proxy** | HTTP apps | Reverse proxy |
| **Clientless** | Browser access | Gateway-based |

---

## Agent Connector

### Installation
```bash
# Download connector
curl -sL https://opensase.io/connector.sh | bash

# Configure
cat > /etc/opensase/connector.yaml << EOF
connector_id: ${CONNECTOR_ID}
api_key: ${API_KEY}
controller: controller.opensase.io:443
apps:
  - id: internal-app
    host: 10.0.1.50
    port: 443
    protocol: https
EOF

# Start
systemctl enable opensase-connector
systemctl start opensase-connector
```

### Health Check
```bash
opensase-connector status
# Connector: healthy
# Apps: 3 registered
# Tunnels: 12 active
```

---

## Application Registration

```yaml
apps:
  - id: internal-wiki
    name: "Internal Wiki"
    type: web
    host: wiki.internal.corp
    port: 443
    protocol: https
    health_check:
      enabled: true
      path: /health
      interval: 30s
    access_policy:
      min_trust_score: 60
      require_mfa: true
      record_session: false

  - id: prod-ssh
    name: "Production SSH"
    type: ssh
    host: 10.0.1.10
    port: 22
    access_policy:
      min_trust_score: 80
      require_mfa: true
      record_session: true
```

---

## WireGuard Tunnel

### Gateway Config
```ini
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = <gateway_private_key>

# Per-session peers are added dynamically
```

### Client Config (Auto-generated)
```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.200.0.x/32
DNS = 10.200.0.1

[Peer]
PublicKey = <gateway_public_key>
Endpoint = gateway.opensase.io:51820
AllowedIPs = 10.0.1.50/32  # Only this app
PersistentKeepalive = 25
```

---

## Micro-Segmentation ACL

```
# Per-tunnel ACL (auto-applied)
ALLOW tunnel-abc → 10.0.1.50:443/tcp LOG
DENY  tunnel-abc → 0.0.0.0/0/* LOG

# User cannot access ANY other internal resource
```

---

## Monitoring

### Metrics
- Active tunnels
- Bytes transferred
- Connection errors
- Health check status

### Alerts
- Connector offline
- App health failed
- Unusual traffic patterns
- ACL violations

---

## Scaling

| Connectors | Concurrent Users | Bandwidth |
|------------|------------------|-----------|
| 1 | 500 | 1 Gbps |
| 3 | 1,500 | 3 Gbps |
| 10 | 5,000 | 10 Gbps |

---

## Security

| Feature | Implementation |
|---------|----------------|
| **mTLS** | Connector ↔ Controller |
| **WireGuard** | User ↔ Gateway |
| **Ephemeral Keys** | New keypair per session |
| **ACL** | Per-tunnel segmentation |
