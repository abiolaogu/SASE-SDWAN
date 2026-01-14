# FlexiWAN Integration Guide

## Overview

OpenSASE integrates with FlexiWAN SD-WAN to provide a unified management and data plane solution. This guide covers the deployment of fleximanage (control plane) and flexiEdge (data plane) with VPP integration.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    OpenSASE Control Plane                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ fleximanage │  │ OpenSASE    │  │    OSSO API             │  │
│  │ (SD-WAN     │←→│ Portal      │←→│    (Rust Backend)       │  │
│  │  Controller)│  │ (React UI)  │  │                         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│         │                                     │                  │
│         ▼               ▼                     ▼                  │
├─────────────────────────────────────────────────────────────────┤
│                    OpenSASE Data Plane                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  flexiEdge  │  │     VPP     │  │      Suricata           │  │
│  │  (Agent)    │←→│ (100 Gbps)  │←→│      (IPS)              │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Deploy Control Plane

```bash
cd docker/flexiwan
docker-compose up -d
```

Access fleximanage at: `http://localhost:3000`

Default credentials:
- Email: `admin@opensase.io`
- Password: Set via `FLEXIWAN_ADMIN_PASSWORD` environment variable

### 2. Deploy Edge Device

```bash
# On each edge device
sudo ./scripts/edge/deploy-edge.sh edge-01 https://manage.opensase.io <activation-token>
```

## Control Plane Components

| Component | Port | Description |
|-----------|------|-------------|
| fleximanage | 3000 | Web UI and API |
| fleximanage | 4433 | Device WebSocket |
| MongoDB | 27017 | Configuration store |
| Redis | 6379 | Session/pub-sub |
| OSSO API | 8081 | OpenSASE orchestrator |
| Portal | 8080 | Unified management UI |

## FlexiWAN API Usage

### Authentication

```rust
use sase_sdwan::FlexiWanApi;

let api = FlexiWanApi::login(
    "https://manage.opensase.io",
    "admin@opensase.io",
    "password"
).await?;
```

### Create Organization

```rust
let org = api.create_organization("ACME Corp").await?;
```

### Register Device

```rust
let device = api.register_device(&org.id, DeviceRegistration {
    name: "branch-nyc".to_string(),
    description: Some("NYC Branch Office".to_string()),
    site: Some("New York".to_string()),
}).await?;
```

### Create Tunnel

```rust
let tunnel = api.create_tunnel(&org.id, TunnelDefinition {
    device_a: device_a.id.clone(),
    device_b: device_b.id.clone(),
    interface_a: "eth0".to_string(),
    interface_b: "eth0".to_string(),
    is_active: true,
}).await?;
```

### Apply Routing Policy

```rust
let policy = api.apply_routing_policy(&org.id, RoutingPolicy {
    name: "voice-priority".to_string(),
    description: Some("Low latency for voice".to_string()),
    rules: vec![
        RoutingRule {
            application: "voip".to_string(),
            priority: 1,
            action: "prefer".to_string(),
            interface: Some("mpls".to_string()),
        }
    ],
    devices: vec![device.id.clone()],
}).await?;
```

## VPP Integration

The edge integration daemon bridges flexiEdge control messages to VPP data plane:

```rust
use sase_sdwan::EdgeIntegration;

let mut integration = EdgeIntegration::new(
    "edge-01",
    config_receiver,
    health_sender,
    vpp_bridge,
);

integration.run().await?;
```

### VPP Commands

```bash
# Show interfaces
vppctl show interface

# Show WireGuard tunnels  
vppctl show wireguard

# Show routing table
vppctl show ip fib

# Show NAT sessions
vppctl show nat44 sessions
```

## Configuration Templates

### Edge Agent Config (`/etc/flexiwan/agent.conf`)

```json
{
    "deviceName": "edge-01",
    "dataPlane": "vpp",
    "vppSocketPath": "/run/vpp/cli.sock",
    "managementUrl": "https://manage.opensase.io",
    "token": "<activation-token>",
    "features": {
        "sdwan": true,
        "firewall": true,
        "nat": true,
        "qos": true,
        "wireguard": true
    }
}
```

### VPP Startup Config (`/etc/vpp/startup.conf`)

```
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
}

cpu {
    main-core 0
    corelist-workers 1-3
}

dpdk {
    uio-driver vfio-pci
    socket-mem 1024
}

plugins {
    plugin dpdk_plugin.so { enable }
    plugin wireguard_plugin.so { enable }
    plugin nat_plugin.so { enable }
}
```

## Troubleshooting

### Edge Not Connecting

1. Check flexiwan service:
```bash
systemctl status flexiwan
journalctl -u flexiwan -f
```

2. Verify token:
```bash
cat /etc/flexiwan/agent.conf | jq .token
```

3. Check network connectivity:
```bash
curl -k https://manage.opensase.io/api/health
```

### VPP Issues

1. Check VPP status:
```bash
systemctl status vpp
vppctl show version
```

2. Check hugepages:
```bash
cat /proc/meminfo | grep Huge
```

3. Check VPP logs:
```bash
tail -f /var/log/vpp/vpp.log
```

### Tunnel Not Establishing

1. Check tunnel status in fleximanage UI
2. Verify WireGuard in VPP:
```bash
vppctl show wireguard peer
```

3. Check firewall (UDP 51820):
```bash
iptables -L -n | grep 51820
```

## Performance Tuning

See [Edge Deployment Guide](EDGE_DEPLOYMENT.md) for:
- Hugepage configuration
- CPU isolation
- DPDK tuning
- NIC optimization
