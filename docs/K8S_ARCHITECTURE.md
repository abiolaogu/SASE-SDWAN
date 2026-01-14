# Kubernetes Architecture Guide

## Overview

OpenSASE Control Plane Platform (OCPP) runs Kubernetes on bare metal at each PoP.

```
┌─────────────────────────────────────────────────────────────────┐
│                          PoP Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                  Kubernetes Control Plane                    │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │ │
│  │  │ API     │  │ Portal  │  │ Observ- │  │ VPP Gateway     │ │ │
│  │  │ Server  │  │ (React) │  │ ability │  │ (gRPC)          │ │ │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────────┬────────┘ │ │
│  │       │            │            │                 │          │ │
│  │       └────────────┴────────────┴─────────────────┘          │ │
│  │                         Cilium CNI                            │ │
│  │                    (eBPF, XDP, WireGuard)                     │ │
│  └──────────────────────────────┬───────────────────────────────┘ │
│                                 │ gRPC                            │
│  ┌──────────────────────────────▼───────────────────────────────┐ │
│  │                    VPP Data Plane (Bare Metal)                │ │
│  │  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌────────────┐  │ │
│  │  │ 100GbE   │  │ WireGuard  │  │ ACLs/    │  │ IPS/DPI    │  │ │
│  │  │ NICs     │  │ Mesh       │  │ NAT      │  │ (OISE)     │  │ │
│  │  └──────────┘  └────────────┘  └──────────┘  └────────────┘  │ │
│  └──────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

### Kubernetes Distribution: Talos Linux

**Why Talos?**
- Immutable, API-driven OS
- No SSH, reduced attack surface
- Built-in secure boot
- Production-ready in minutes

**Node Layout (per PoP):**
| Role | Count | Specs |
|------|-------|-------|
| Control Plane | 3 | 32GB RAM, 500GB SSD |
| Worker (optional) | 0-2 | 64GB RAM, 1TB SSD |

### CNI: Cilium

**Features Enabled:**
- eBPF kube-proxy replacement
- XDP load balancer acceleration
- WireGuard node encryption
- Hubble observability
- Cluster mesh for multi-PoP

### Networking

**Pod Network:** 10.244.0.0/16
**Service Network:** 10.96.0.0/12
**Load Balancer Mode:** DSR (Direct Server Return)

---

## Services Deployed

| Service | Replicas | Purpose |
|---------|----------|---------|
| api-server | 3 | REST/gRPC API |
| portal | 2 | Admin UI |
| vpp-gateway | DaemonSet | VPP integration |
| prometheus | 1 | Metrics |
| grafana | 1 | Dashboards |

---

## Cluster Mesh

Multi-PoP connectivity via Cilium Cluster Mesh:

```
  NYC ◄────► FRA ◄────► SGP
   │          │          │
   └──────────┼──────────┘
              │
            Global
           Services
```

**Global Services:**
- `api-server-global` - Available at any PoP
- `portal-global` - Portal accessible anywhere

---

## VPP Integration

```
┌─────────────────────┐     gRPC      ┌─────────────────────┐
│   K8s Services      │◄─────────────►│   VPP Gateway       │
│   (api-server)      │   :50052      │   (DaemonSet)       │
└─────────────────────┘               └──────────┬──────────┘
                                                 │
                                                 │ Unix Socket
                                                 │ /run/vpp/cli.sock
                                                 ▼
                                      ┌─────────────────────┐
                                      │   VPP Data Plane    │
                                      │   (Bare Metal)      │
                                      └─────────────────────┘
```

**VPP Gateway API:**
- `GetInterfaces()` - List VPP interfaces
- `CreateTunnel()` - Create WireGuard tunnel
- `ApplyAcl()` - Configure ACL rules
- `GetStats()` - Traffic statistics

---

## Deployment

### 1. Provision Talos Nodes

```bash
# Generate config
talosctl gen config opensase-nyc1 \
  https://10.0.0.10:6443 \
  --config-patch @talos-config.yaml

# Apply to nodes
talosctl apply-config --nodes 10.0.0.11 -f controlplane.yaml
talosctl apply-config --nodes 10.0.0.12 -f controlplane.yaml
talosctl apply-config --nodes 10.0.0.13 -f controlplane.yaml

# Bootstrap cluster
talosctl bootstrap --nodes 10.0.0.11
```

### 2. Install Cilium

```bash
helm install cilium cilium/cilium \
  --namespace kube-system \
  --values cilium/values.yaml
```

### 3. Deploy Services

```bash
kubectl apply -f services/opensase-control-plane.yaml
kubectl apply -f observability/kube-prometheus-stack.yaml
```

### 4. Configure Cluster Mesh

```bash
cilium clustermesh enable
cilium clustermesh connect --destination-context opensase-fra1
```

---

## Monitoring

**Metrics Endpoints:**
- Prometheus: `http://prometheus.monitoring:9090`
- Grafana: `https://grafana.<pop>.opensase.io`
- Hubble UI: `https://hubble.<pop>.opensase.io`

**Key Dashboards:**
- VPP Overview
- Cilium Network Flows
- API Server Performance
- Cluster Mesh Status

---

## Security

- **Pod Security:** Restricted (no root, no privilege escalation)
- **Network Encryption:** WireGuard between all nodes
- **RBAC:** Least privilege service accounts
- **Secrets:** External Secrets Operator with Vault
