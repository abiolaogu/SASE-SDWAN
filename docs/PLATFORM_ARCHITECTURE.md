# OpenSASE Enterprise SASE Platform

## Platform Overview

OpenSASE is a carrier-grade, 100+ Gbps Secure Access Service Edge (SASE) platform built entirely on open-source technologies and deployed on bare-metal infrastructure.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         OpenSASE Enterprise SASE Platform                 │
├──────────────────────────────────────────────────────────────────────────┤
│  SOC OPERATIONS                                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                    │
│  │ SIEM Forward │  │    SOAR      │  │    Case      │                    │
│  │ Splunk/ELK   │  │  Playbooks   │  │  Management  │                    │
│  │ Sentinel/QR  │  │  Automation  │  │  Forensics   │                    │
│  └──────────────┘  └──────────────┘  └──────────────┘                    │
├──────────────────────────────────────────────────────────────────────────┤
│  SECURITY SERVICES                                                        │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │  DDoS   │ │   IPS   │ │ Email   │ │  RBI    │ │ Threat  │            │
│  │ 100Gbps │ │Suricata │ │Security │ │ Browser │ │  Intel  │            │
│  │ XDP/VPP │ │Hyperscan│ │SPF/DKIM │ │Isolation│ │STIX/OTX │            │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘            │
├──────────────────────────────────────────────────────────────────────────┤
│  ACCESS CONTROL                                                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │      ZTNA       │  │   SWG / CASB    │  │      DLP        │          │
│  │  Trust Engine   │  │  URL Filtering  │  │ Content Inspect │          │
│  │  Device Posture │  │  SaaS Control   │  │ Policy Enforce  │          │
│  │  Micro-Segment  │  │  SSL Inspect    │  │                 │          │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘          │
├──────────────────────────────────────────────────────────────────────────┤
│  NETWORK LAYER                                                            │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │                 VPP DATA PLANE (100+ Gbps)                   │        │
│  │  DPDK NICs │ WireGuard Tunnels │ CG-NAT │ ACL Firewall      │        │
│  └─────────────────────────────────────────────────────────────┘        │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │               SD-WAN (FlexiWAN Integration)                  │        │
│  │  Path Selection │ QoE Optimization │ Multi-Link │ Failover  │        │
│  └─────────────────────────────────────────────────────────────┘        │
├──────────────────────────────────────────────────────────────────────────┤
│  CONTROL PLANE                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                    │
│  │ Kubernetes   │  │   Portal     │  │  APIs        │                    │
│  │ Talos+Cilium │  │  React UI    │  │ REST/gRPC   │                    │
│  │ eBPF Network │  │  Dashboard   │  │ xDS         │                    │
│  └──────────────┘  └──────────────┘  └──────────────┘                    │
├──────────────────────────────────────────────────────────────────────────┤
│  INFRASTRUCTURE                                                           │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  BARE METAL PROVIDERS (NO HYPERSCALERS)                      │        │
│  │  Equinix │ OVH │ Hetzner │ Scaleway │ Leaseweb │ PhoenixNAP │        │
│  └─────────────────────────────────────────────────────────────┘        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐        │
│  │  PRIVATE BACKBONE │  │   IXP PEERING    │  │  IaC AUTOMATION │        │
│  │  Megaport         │  │   DE-CIX, AMS-IX │  │  Terraform      │        │
│  │  PacketFabric     │  │   LINX, Equinix  │  │  Ansible        │        │
│  └──────────────────┘  └──────────────────┘  └─────────────────┘        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Crate Inventory (33 Crates)

### Core Platform

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-common` | Shared types and utilities | ~500 |
| `sase-policy` | Unified policy engine | ~800 |
| `sase-tenant` | Multi-tenant management | ~600 |
| `sase-billing` | Usage metering and billing | ~500 |

### Data Plane (100+ Gbps)

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-vpp` | VPP management API | ~1,500 |
| `sase-dataplane` | Packet processing | ~1,000 |
| `sase-xdp` | XDP/eBPF programs | ~800 |
| `vpp-gateway` | VPP-K8s integration | ~600 |

### Security Services

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-ddos` | DDoS mitigation (100Gbps) | ~1,200 |
| `sase-ips` | IPS with Hyperscan | ~1,000 |
| `sase-dlp` | Data Loss Prevention | ~800 |
| `sase-casb` | SaaS Security Broker | ~700 |
| `sase-email-security` | Email protection | ~900 |
| `sase-rbi` | Browser Isolation | ~800 |
| `sase-threat-intel` | IOC correlation | ~700 |

### Layer 7 Gateway

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-gateway` | API Gateway | ~600 |
| `sase-l7` | L7 proxy backend | ~800 |
| `sase-xds` | xDS control plane | ~700 |
| `sase-envoy-filters` | WASM filters | ~1,000 |
| `sase-usie` | Unified Security Inspection | ~900 |

### Access Control

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-ztna` | Zero Trust Access | ~2,500 |
| `sase-fpe` | Format-Preserving Encryption | ~500 |

### SD-WAN

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-sdwan` | SD-WAN orchestration | ~1,200 |
| `sase-path` | Path selection | ~600 |
| `sase-resilience` | HA and failover | ~500 |

### Intelligence

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-ml` | ML inference | ~800 |
| `sase-behavioral` | Behavioral analysis | ~700 |
| `sase-ite` | Traffic engineering | ~600 |

### Infrastructure

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-orchestrator` | PoP orchestration | ~1,000 |
| `sase-backbone` | Private backbone | ~800 |
| `sase-peering` | IXP peering | ~700 |
| `sase-compliance` | Regulatory compliance | ~500 |

### SOC Operations

| Crate | Description | Lines |
|-------|-------------|-------|
| `sase-soc` | Security Operations (16 modules) | ~6,500 |

---

## Performance Targets

| Metric | Target | Technology |
|--------|--------|------------|
| **Throughput** | 100+ Gbps | VPP + DPDK |
| **Latency** | < 5μs | Single-pass pipeline |
| **PPS** | 50M+ | XDP pre-filtering |
| **TLS Inspection** | 20 Gbps | WASM filters |
| **IPS Matching** | < 1μs | Hyperscan |
| **IOC Lookup** | < 1μs | Bloom filters |

---

## Deployment Architecture

### Per-PoP Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         BARE METAL SERVER                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      VPP DATA PLANE                        │  │
│  │  DPDK → Classify → IPS → NAT → WireGuard → TX             │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │ API                               │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                   KUBERNETES (Talos)                       │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐      │  │
│  │  │ Control │  │  Envoy  │  │  Portal │  │ Monitor │      │  │
│  │  │  Plane  │  │ Proxies │  │   UI    │  │ Stack   │      │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘      │  │
│  │                     Cilium eBPF Mesh                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Global Topology

```
                          ┌─────────────────┐
                          │  Orchestrator   │
                          │  (Central)      │
                          └────────┬────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
   ┌─────────┐               ┌─────────┐               ┌─────────┐
   │  PoP    │───WireGuard───│  PoP    │───WireGuard───│  PoP    │
   │ EU-West │               │ US-East │               │ APAC    │
   └─────────┘               └─────────┘               └─────────┘
        │                          │                          │
        └──────────Private Backbone (Megaport)────────────────┘
```

---

## Technology Stack

### Core Technologies

| Component | Technology |
|-----------|------------|
| **Language** | Rust (100%) |
| **Data Plane** | FD.io VPP + DPDK |
| **Packet Matching** | Intel Hyperscan |
| **Tunneling** | WireGuard |
| **Container Runtime** | Kubernetes (Talos) |
| **Service Mesh** | Cilium (eBPF) |
| **L7 Proxy** | Envoy + WASM |
| **ML Inference** | ONNX Runtime |
| **IaC** | Terraform + Ansible |

### Monitoring Stack

| Component | Technology |
|-----------|------------|
| **Metrics** | Prometheus |
| **Dashboards** | Grafana |
| **Logs** | OpenTelemetry |
| **Traces** | Jaeger |

---

## Security Features

### Network Security

- **DDoS Mitigation**: 100+ Gbps volumetric, 50M PPS
- **IPS/IDS**: Suricata rules via Hyperscan
- **Firewall**: Stateful L4 + L7 policies
- **NAT**: CG-NAT with port preservation

### Access Security

- **ZTNA**: Continuous trust evaluation
- **Device Posture**: EDR, patch, encryption checks
- **MFA**: TOTP, WebAuthn, push
- **SSO**: SAML, OIDC, OAuth2

### Data Security

- **DLP**: Pattern + ML detection
- **TLS Inspection**: Full MITM proxy
- **CASB**: SaaS visibility and control
- **FPE**: Format-preserving encryption

### Threat Protection

- **Threat Intel**: STIX/TAXII, OTX, MISP
- **Email Security**: SPF/DKIM/DMARC, sandbox
- **Browser Isolation**: Pixel streaming
- **Malware**: YARA + ML detection

---

## Documentation Index

| Document | Description |
|----------|-------------|
| [SOC_ARCHITECTURE.md](docs/SOC_ARCHITECTURE.md) | SOC platform overview |
| [SOC_INTEGRATION_GUIDE.md](docs/SOC_INTEGRATION_GUIDE.md) | SIEM/EDR setup |
| [PLAYBOOK_DEVELOPMENT.md](docs/PLAYBOOK_DEVELOPMENT.md) | SOAR playbooks |
| [FORENSICS_PROCEDURES.md](docs/FORENSICS_PROCEDURES.md) | Evidence collection |
| [TRUST_SCORING.md](docs/TRUST_SCORING.md) | ZTNA trust calculation |
| [SESSION_RECORDING.md](docs/SESSION_RECORDING.md) | Activity recording |
| [CONNECTOR_DEPLOYMENT.md](docs/CONNECTOR_DEPLOYMENT.md) | App connector setup |

---

## Getting Started

### Prerequisites

- Bare metal server (32+ cores, 128GB RAM, 100GbE NICs)
- Ubuntu 22.04 or Talos Linux
- DPDK-compatible NICs (Intel, Mellanox)

### Quick Deploy

```bash
# Clone repository
git clone https://github.com/opensase/opensase-core

# Deploy PoP
cd deployment
./deploy-pop.sh --provider equinix --region amsterdam

# Verify
curl -k https://localhost:8443/health
```

---

## License

Apache 2.0
