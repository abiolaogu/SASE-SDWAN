# OpenSASE-Lab Architecture

This document describes the architecture of OpenSASE-Lab, a fully reproducible SASE (Secure Access Service Edge) security lab.

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Internet["Internet / Remote Users"]
        USER[👤 Remote User<br/>with Ziti Desktop Edge]
    end

    subgraph PoP["Security PoP (Hub) - 10.200.0.0/24"]
        direction TB
        
        subgraph Control["Control Plane"]
            FWC[FlexiWAN Controller<br/>:3000]
            ZITI_CTRL[OpenZiti Controller<br/>:1280]
            WAZUH[Wazuh Manager<br/>:1514/1515]
            KC[Keycloak<br/>:8443]
        end
        
        subgraph Data["Data Plane"]
            SPOP[Security Gateway<br/>Suricata IPS + Unbound DNS]
            ZITI_ER_POP[OpenZiti Edge Router<br/>:3022]
        end
        
        subgraph Observability["Observability"]
            PROM[Prometheus<br/>:9090]
            GRAF[Grafana<br/>:3001]
            WAZUH_DASH[Wazuh Dashboard<br/>:5601]
        end
        
        PORTAL[Unified Portal<br/>:8080]
    end

    subgraph BranchA["Branch A - 10.201.0.0/24"]
        FWE_A[FlexiWAN Edge A]
        ZITI_ER_A[Ziti Router A]
        APP1[🔒 App1<br/>Private Nginx]
        WA_A[Wazuh Agent]
    end

    subgraph BranchB["Branch B - 10.202.0.0/24"]
        FWE_B[FlexiWAN Edge B]
        ZITI_ER_B[Ziti Router B]
        APP2[🔒 App2<br/>Private HTTPBin]
        WA_B[Wazuh Agent]
    end

    subgraph BranchC["Branch C - 10.203.0.0/24"]
        FWE_C[FlexiWAN Edge C]
        WA_C[Wazuh Agent]
    end

    %% ZTNA Flow
    USER -->|"1. ZTNA mTLS"| ZITI_ER_POP
    ZITI_ER_POP -->|"Ziti Fabric"| ZITI_ER_A
    ZITI_ER_POP -->|"Ziti Fabric"| ZITI_ER_B
    ZITI_ER_A -->|"Local"| APP1
    ZITI_ER_B -->|"Local"| APP2

    %% SD-WAN Flow
    FWE_A & FWE_B & FWE_C -->|"2. WireGuard VPN"| SPOP
    SPOP -->|"Inspected Traffic"| FWC

    %% Logging Flow
    WA_A & WA_B & WA_C -.->|"3. Syslog/Filebeat"| WAZUH
    SPOP -.->|"Suricata eve.json"| WAZUH

    %% Metrics Flow
    SPOP & FWE_A & FWE_B & FWE_C -.->|"4. Metrics"| PROM
    PROM --> GRAF

    %% Portal Integrations
    PORTAL --> KC
    PORTAL --> FWC
    PORTAL --> ZITI_CTRL
    PORTAL --> WAZUH
```

## Component Overview

### 1. SD-WAN Layer (FlexiWAN)

| Component | Image | Purpose |
|-----------|-------|---------|
| flexiwan-controller | `flexiwan/flexiwan` | Central management, policy distribution |
| flexiwan-mongo | `mongo:6` | Controller database |
| branch-a/b/c | `flexiwan/flexiwan-router` | Edge routers with WireGuard tunnels |

**Key Features:**
- WireGuard-based VPN tunnels (fast, modern cryptography)
- Application-aware routing
- Link quality monitoring (latency, jitter, packet loss)
- Automatic failover between WAN links

### 2. Security PoP Gateway

| Component | Technology | Purpose |
|-----------|------------|---------|
| security-pop | Alpine Linux | Base OS for gateway |
| Suricata | IPS Mode | Inline threat detection and prevention |
| Unbound | DNS Resolver | DNS filtering with query logging |
| nftables | Firewall | Zone-based policy enforcement |

**Traffic Flow:**
```
Branch → WireGuard Tunnel → Security PoP → Suricata IPS → Internet
                                    ↓
                            Unbound DNS (if DNS query)
```

### 3. Zero Trust Network Access (OpenZiti)

| Component | Purpose |
|-----------|---------|
| ziti-controller | PKI, identity management, policy engine |
| ziti-router-pop | PoP-side edge router (public listener) |
| ziti-router-a/b | Branch-side edge routers (hosts services) |

**Zero Trust Principles:**
- Apps have no public IP or ports (dark services)
- Access requires enrolled identity + policy match
- All traffic is mTLS encrypted end-to-end
- Session-level authorization with posture checks

### 4. Security Visibility (Wazuh)

| Component | Purpose |
|-----------|---------|
| wazuh-manager | Log collection, analysis, alerting |
| wazuh-indexer | OpenSearch-based log storage |
| wazuh-dashboard | Security analytics UI |

**Log Sources:**
- Suricata IDS/IPS alerts (eve.json)
- FlexiWAN system logs
- OpenZiti audit logs
- OS-level events from all nodes

### 5. Identity (Keycloak)

| Component | Purpose |
|-----------|---------|
| keycloak | OIDC/SAML identity provider |
| keycloak-db | PostgreSQL for Keycloak |

**Realm: opensase-lab**
- Client: `portal-app` (Unified Portal)
- Client: `grafana` (Grafana SSO)
- Roles: `admin`, `operator`, `viewer`

### 6. Observability (Prometheus + Grafana)

| Exporter | Metrics |
|----------|---------|
| node_exporter | CPU, memory, disk, network |
| suricata_exporter | IPS stats, flow counts |
| flexiwan_exporter | Tunnel status, link quality |
| ziti_exporter | Session counts, policy hits |

**Dashboards:**
- SD-WAN Overview (tunnel health, bandwidth)
- Security PoP (IPS alerts, DNS queries)
- ZTNA Sessions (active sessions, policy decisions)
- System Health (resource utilization)

### 7. Unified Portal

| Component | Technology | Purpose |
|-----------|------------|---------|
| portal-backend | FastAPI + Python | API aggregation, SSO |
| portal-frontend | React + Vite | Dashboard UI |

**Aggregated Views:**
- Sites & Tunnels (FlexiWAN API)
- Security Policies (Suricata stats API)
- ZTNA Apps (Ziti Management API)
- Security Alerts (Wazuh API)

---

## Network Architecture

### Docker Networks

| Network | Subnet | Purpose |
|---------|--------|---------|
| pop-net | 10.200.0.0/24 | Security PoP components |
| branch-a-net | 10.201.0.0/24 | Branch A isolated network |
| branch-b-net | 10.202.0.0/24 | Branch B isolated network |
| branch-c-net | 10.203.0.0/24 | Branch C isolated network |
| ziti-fabric | 10.210.0.0/16 | OpenZiti overlay network |
| mgmt-net | 172.30.0.0/24 | Management plane (Wazuh, Prometheus) |

### Port Mappings (Host Access)

| Port | Service | Purpose |
|------|---------|---------|
| 3000 | FlexiWAN Controller | SD-WAN management UI |
| 3001 | Grafana | Observability dashboards |
| 5601 | Wazuh Dashboard | Security analytics |
| 8080 | Unified Portal | Single pane of glass |
| 8443 | Keycloak | Identity provider |
| 9090 | Prometheus | Metrics (internal use) |

---

## Data Flows

### 1. Branch Internet Breakout (Policy Enforcement)

```mermaid
sequenceDiagram
    participant User as Branch User
    participant Edge as FlexiWAN Edge
    participant PoP as Security PoP
    participant IPS as Suricata IPS
    participant DNS as Unbound DNS
    participant Net as Internet

    User->>Edge: HTTP request to example.com
    Edge->>PoP: WireGuard tunnel
    PoP->>DNS: DNS query for example.com
    DNS-->>PoP: IP address (logged)
    PoP->>IPS: Inspect traffic
    IPS-->>PoP: Allow/Block decision
    alt Allowed
        PoP->>Net: Forward request
        Net-->>User: Response (via tunnel)
    else Blocked
        IPS-->>User: Block page / RST
        IPS->>Wazuh: Alert: Blocked threat
    end
```

### 2. ZTNA Application Access

```mermaid
sequenceDiagram
    participant User as Remote User
    participant ZDE as Ziti Desktop Edge
    participant ZRP as Ziti Router (PoP)
    participant ZRA as Ziti Router (Branch)
    participant App as Private App

    User->>ZDE: Access app1.ziti
    ZDE->>ZRP: mTLS connection (identity: user@corp)
    ZRP->>ZRP: Check policy: user → app1
    alt Authorized
        ZRP->>ZRA: Fabric relay
        ZRA->>App: Local connection
        App-->>User: Response (end-to-end encrypted)
    else Denied
        ZRP-->>User: Access Denied
        ZRP->>Wazuh: Audit: Policy violation
    end
```

### 3. Security Alert Flow

```mermaid
sequenceDiagram
    participant IPS as Suricata
    participant FB as Filebeat
    participant WM as Wazuh Manager
    participant WI as Wazuh Indexer
    participant WD as Wazuh Dashboard
    participant Portal as Unified Portal

    IPS->>FB: eve.json (alert)
    FB->>WM: Forward log
    WM->>WM: Decode & correlate
    WM->>WI: Index alert
    WI->>WD: Available for query
    Portal->>WM: GET /alerts (API)
    WM-->>Portal: Alert summary
```

---

## Deployment Profiles

### Full Profile (16GB RAM, 8 CPU)
All components running with recommended resource allocations.

### Lite Profile (8GB RAM, 4 CPU)
- Wazuh Indexer: Single node, no replication
- Prometheus: Reduced retention (1 day)
- Grafana: Fewer preloaded dashboards
- Sample apps: Reduced replicas

---

## Technology Stack Summary

| Layer | Technology | License |
|-------|------------|---------|
| SD-WAN | FlexiWAN | AGPL-3.0 |
| VPN | WireGuard | GPL-2.0 |
| IPS | Suricata | GPL-2.0 |
| DNS | Unbound | BSD |
| ZTNA | OpenZiti | Apache-2.0 |
| SIEM | Wazuh | GPL-2.0 |
| Identity | Keycloak | Apache-2.0 |
| Metrics | Prometheus | Apache-2.0 |
| Dashboards | Grafana | AGPL-3.0 |
| Portal Backend | FastAPI | MIT |
| Portal Frontend | React | MIT |
