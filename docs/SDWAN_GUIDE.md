# SD-WAN Layer Guide

Comprehensive guide for the FlexiWAN SD-WAN layer in OpenSASE-Lab.

## Architecture

```
                     ┌─────────────────────────────────────┐
                     │         Security PoP (Hub)          │
                     │  ┌─────────────┐ ┌─────────────┐   │
                     │  │  FlexiWAN   │ │   Security  │   │
                     │  │ Controller  │ │   Gateway   │   │
                     │  └─────────────┘ └─────────────┘   │
                     │         10.200.0.0/24               │
                     └──────────────┬──────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
    WireGuard │           WireGuard │           WireGuard │
      Tunnel  ▼             Tunnel  ▼             Tunnel  ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│    Branch A     │   │    Branch B     │   │    Branch C     │
│  ┌───────────┐  │   │  ┌───────────┐  │   │  ┌───────────┐  │
│  │ WAN1│WAN2 │  │   │  │ WAN1│WAN2 │  │   │  │ WAN1│WAN2 │  │
│  └───────────┘  │   │  └───────────┘  │   │  └───────────┘  │
│  ┌───────────┐  │   │  ┌───────────┐  │   │  ┌───────────┐  │
│  │Corp│Guest │  │   │  │Corp│Guest │  │   │  │Corp│Guest │  │
│  │VRF │VRF   │  │   │  │VRF │VRF   │  │   │  │VRF │VRF   │  │
│  └───────────┘  │   │  └───────────┘  │   │  └───────────┘  │
│  10.201.0.0/24  │   │  10.202.0.0/24  │   │  10.203.0.0/24  │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

## Features

### 1. Network Segmentation (VRF)

Two logical segments are configured:

| Segment | VLAN ID | VRF ID | Purpose |
|---------|---------|--------|---------|
| **corp** | 100 | 1 | Corporate traffic → routes via PoP |
| **guest** | 200 | 2 | Guest traffic → local internet breakout |

### 2. Policy-Based Routing

| Segment | Route | Description |
|---------|-------|-------------|
| Corp | Hub (PoP) | All traffic inspected by Suricata |
| Guest | Direct | Local internet breakout via WAN1 |

### 3. Dual WAN with Failover

Each branch has two WAN interfaces:

| Interface | Metric | Role |
|-----------|--------|------|
| WAN1 (eth0) | 100 | Primary |
| WAN2 (eth1) | 200 | Backup |

**Failover behavior:**
- Health probes every 5 seconds
- Failover if latency > 100ms or packet loss > 5%
- Automatic failback when primary recovers

---

## Quick Start

### 1. Start the SD-WAN Stack

```bash
# Bootstrap controller configuration
./scripts/flexiwan-bootstrap.sh

# Generate edge configurations
./scripts/flexiwan-edge-bootstrap.sh

# Start all SD-WAN components
make up-sdwan
```

### 2. Verify Connectivity

```bash
# Run SD-WAN tests
./scripts/test-sdwan.sh
```

### 3. Access Management UI

- **FlexiWAN Controller**: http://localhost:3000
- **Credentials**: See `.env` file

---

## Adding a New Branch

**Time required: < 10 minutes**

### Step 1: Run the Add Branch Script

```bash
./scripts/add-branch.sh branch-d 4
```

This creates:
- `docker/flexiwan-edge/branch-d/device.conf`
- `docker/flexiwan-edge/branch-d/docker-compose.yml`

### Step 2: Add to docker-compose.yml

Copy the generated service definition:

```yaml
services:
  # ... existing services ...
  
  branch-d:
    image: flexiwan/flexiwan-router:latest
    container_name: branch-d
    # ... (see generated file)

networks:
  # ... existing networks ...
  
  branch-d-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.204.0.0/24
```

### Step 3: Get Device Token

1. Open FlexiWAN UI: http://localhost:3000
2. Go to **Inventory** → **Device Tokens**
3. Click **Create Token** for `branch-d`
4. Add to `.env`:
   ```
   BRANCH_D_TOKEN=<token>
   ```

### Step 4: Start the Branch

```bash
docker compose up -d branch-d
```

### Step 5: Verify Enrollment

- Check FlexiWAN UI → **Devices**
- Run: `./scripts/test-sdwan.sh`

---

## Configuration Reference

### Device Configuration

Location: `docker/flexiwan-edge/<branch>/device.conf`

```ini
[device]
name = branch-a
description = OpenSASE Lab Edge

[interface.wan1]
name = eth0
type = wan
ip = 10.200.0.11
gateway = 10.200.0.1
metric = 100

[interface.wan2]
name = eth1
type = wan
ip = 10.200.0.21
gateway = 10.200.0.1
metric = 200

[interface.lan]
name = eth2
type = lan
ip = 10.201.0.1
subnet = 10.201.0.0/24

[vlan.corp]
id = 100
interface = eth2
segment = 1

[vlan.guest]
id = 200
interface = eth2
segment = 2

[tunnel.to-pop]
type = wireguard
peer = pop-gateway
interface = wan1
fallback_interface = wan2
```

### Segment/VRF Configuration

Created via `flexiwan-bootstrap.sh`:

```json
{
  "name": "corp",
  "segmentId": 1,
  "description": "Corporate traffic - routes via PoP"
}
```

### Routing Policies

| Policy | Match | Action |
|--------|-------|--------|
| corp-via-pop | segment=corp | Route to hub |
| guest-local-breakout | segment=guest | Direct internet |

---

## Testing

### Overlay Connectivity

```bash
# From branch-a to PoP
docker exec branch-a ping -c 3 10.200.0.1

# Branch-to-branch via overlay
docker exec branch-a ping -c 3 10.202.0.1
```

### VRF Routing

```bash
# Check corp routing table (VRF 1)
docker exec branch-a ip route show table 1

# Check guest routing table (VRF 2)
docker exec branch-a ip route show table 2
```

### Failover Test

```bash
# Simulate WAN1 failure
docker exec branch-a ip link set eth0 down

# Verify connectivity via WAN2
docker exec branch-a ping -c 3 10.200.0.1

# Restore WAN1
docker exec branch-a ip link set eth0 up
```

### Full Test Suite

```bash
./scripts/test-sdwan.sh
```

---

## Troubleshooting

### Edge Not Connecting

1. Check token: `cat .device-tokens | grep branch-a`
2. Verify network: `docker exec branch-a ping flexiwan-controller`
3. Check logs: `docker logs branch-a`

### Tunnel Down

1. Check WireGuard: `docker exec branch-a wg show`
2. Verify peer config: `docker exec branch-a cat /etc/wireguard/wg0.conf`
3. Check firewall: Ensure UDP 51820 is allowed

### VRF Not Working

1. Check VLAN interface: `docker exec branch-a ip link show eth2.100`
2. Verify routing rules: `docker exec branch-a ip rule show`
3. Check segment assignment in FlexiWAN UI

---

## FlexiWAN API Reference

### Authentication

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@opensase.lab", "password": "..."}'
```

### List Devices

```bash
curl http://localhost:3000/api/devices \
  -H "Authorization: Bearer <token>"
```

### Create Segment

```bash
curl -X POST http://localhost:3000/api/organizations/<org>/segments \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "iot", "segmentId": 3}'
```

### Create Policy

```bash
curl -X POST http://localhost:3000/api/organizations/<org>/policies \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "iot-policy",
    "match": {"segment": "iot"},
    "action": {"type": "route", "path": "hub"}
  }'
```

---

## Limitations

| Feature | FlexiWAN Support | Workaround |
|---------|------------------|------------|
| Full VRF isolation | Partial (segments) | Use VLANs + routing tables |
| BGP peering | Not in OSS version | Static routes |
| Advanced QoS | Limited | Use tc/nftables directly |

---

## Related Documentation

- [Architecture Overview](ARCHITECTURE.md)
- [Performance Tuning](PERFORMANCE_NOTES.md)
- [FlexiWAN Docs](https://docs.flexiwan.com/)
