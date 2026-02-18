# Gap Analysis -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Executive Summary

This gap analysis evaluates the OpenSASE-Lab / SASE-SDWAN platform against production-grade SASE requirements. The platform currently operates as a reproducible security lab using Docker Compose with FlexiWAN (SD-WAN), OpenZiti (ZTNA), Suricata (IPS), Wazuh (SIEM), and Keycloak (SSO). A parallel effort in `opensase-core/` implements a high-performance Rust data plane targeting 100 Gbps throughput with eBPF/XDP acceleration. This document identifies gaps between the current state and a production SASE/SD-WAN offering.

## 2. Methodology

- Source code review of all directories: `opensase-core/`, `opensase-portal/`, `opensase-clients/`, `api/`, `cli/`, `edge/`, `ml/`, `components/`, `portal/`, `infra/`, `docker/`, `scripts/`, `sdk/`
- Cargo.toml dependency analysis for Rust crates
- Docker Compose service topology mapping
- OpenAPI specification review (`opensase-core/docs/openapi/opensase-api.yaml`)
- Kubernetes manifest analysis (`infra/k8s/`)

## 3. Current State Assessment

### 3.1 Architecture Components (Implemented)

| Component | Location | Language | Maturity |
|-----------|----------|----------|----------|
| SD-WAN Controller | `docker/flexiwan-controller/` | Third-party (FlexiWAN) | Lab-ready |
| SD-WAN Edge Routers | `docker/flexiwan-edge/` | Third-party (FlexiWAN) | Lab-ready |
| Security PoP (IPS + DNS) | `docker/security-pop/` | Alpine + Suricata + Unbound | Lab-ready |
| ZTNA Controller | `docker/openziti-controller/` | Third-party (OpenZiti) | Lab-ready |
| ZTNA Routers | `docker/openziti-router/` | Third-party (OpenZiti) | Lab-ready |
| SIEM | `docker/wazuh/` | Third-party (Wazuh 4.7) | Lab-ready |
| Identity Provider | `docker/keycloak/` | Third-party (Keycloak 23) | Lab-ready |
| Portal Backend (Python) | `portal/backend/app/main.py` | Python/FastAPI | Prototype |
| Portal Backend (Rust) | `portal/backend/src/main.rs` | Rust/Axum | Prototype |
| Portal Frontend (React) | `opensase-portal/src/` | TypeScript/React/Vite | Prototype |
| Portal Frontend (Next.js) | `portal/src/` | TypeScript/Next.js | Scaffold |
| Developer API | `api/src/` | Rust/Axum + utoipa | Prototype |
| CLI | `cli/src/` | Rust/clap | Prototype |
| Edge Appliance | `edge/src/` | Rust/Tokio | Prototype |
| ML Threat Engine | `ml/inference/src/` | Rust/ONNX | Prototype |
| OpenSASE Core Data Plane | `opensase-core/crates/` | Rust (45+ crates) | In Progress |
| UPO Component | `components/upo/` | Python/Pydantic | Functional |
| QoE Selector | `components/qoe-selector/` | Python/Pydantic | Functional |
| CASB-Lite | `components/casb-lite/` | Python/Pydantic | Functional |
| DLP-Lite | `components/dlp-lite/` | Python/Pydantic | Functional |
| Client (Core) | `client/core/` | Rust | Scaffold |
| Clients (Platform) | `opensase-clients/` | Kotlin/Swift/C# | Scaffold |
| SDKs | `sdk/`, `opensase-core/sdks/` | Go/Python/TS/Rust | Scaffold |
| Observability | `docker/prometheus/`, `docker/grafana/` | Prometheus + Grafana | Lab-ready |

### 3.2 Infrastructure Components

| Component | Location | Status |
|-----------|----------|--------|
| Docker Compose (Full) | `docker-compose.yml` | Complete |
| Docker Compose (Lite) | `docker-compose.lite.yml` | Complete |
| Kubernetes Manifests | `infra/k8s/` | Draft |
| Ansible Playbooks | `infra/ansible/` | Draft |
| Terraform | `terraform/opensase/` | Scaffold |
| Bare Metal Deploy | `infra/bare-metal/` | Draft |
| Hyperscaler Config | `infra/hyperscaler/` | Scaffold |
| Self-Hosted Services | `infra/self-hosted/` | Draft |
| VPP Data Plane Scripts | `opensase-core/vpp/` | Draft |
| eBPF/XDP Programs | `opensase-core/bpf/` | Prototype |

### 3.3 OpenSASE Core Crates (45 crates in workspace)

| Category | Crates | Status |
|----------|--------|--------|
| Security Services | sase-policy, sase-dlp, sase-casb, sase-ips, sase-ztna, sase-ddos, sase-fpe | Cargo.toml present, src partially implemented |
| Networking | sase-dataplane, sase-xdp, sase-vpp, sase-path, sase-sdwan, sase-backbone, sase-peering | Cargo.toml present, src partially implemented |
| Platform | sase-gateway, sase-apigw, sase-orchestrator, sase-tenant, sase-billing, sase-resilience | Cargo.toml present, minimal src |
| ML/Analytics | sase-ml, sase-behavioral, sase-soc, sase-threat-intel | Cargo.toml present, minimal src |
| Business Apps | sase-crm, sase-support, sase-ecommerce, sase-payments, sase-hr, sase-marketing, sase-forms, sase-scheduling | Scaffold |
| Infrastructure | sase-xds (Envoy xDS), sase-envoy-filters, sase-l7, sase-cloud-connector, sase-ite | Scaffold |
| SDK | opensase-sdk | Prototype with domain modules |

## 4. Gap Identification

### 4.1 Critical Gaps (Must-Fix for Production)

| ID | Gap | Current State | Required State | Priority |
|----|-----|---------------|----------------|----------|
| G-01 | No persistent database | In-memory state in Rust backends, MongoDB only for FlexiWAN | YugabyteDB/ScyllaDB for tenant/policy/site data | P0 |
| G-02 | No message broker | Direct HTTP calls between services | Redpanda/NATS JetStream for event-driven architecture | P0 |
| G-03 | No production caching layer | No cache beyond in-process Moka | DragonflyDB for distributed session/policy cache | P0 |
| G-04 | Dual portal backends | Both Python FastAPI and Rust Axum in `portal/backend/` | Consolidate on Rust Axum backend | P1 |
| G-05 | No TLS termination | HTTP-only portal and API access | TLS everywhere with cert-manager or Caddy | P0 |
| G-06 | No multi-tenancy in data layer | Single-tenant lab environment | Per-tenant data isolation, row-level security | P0 |
| G-07 | No CI/CD pipeline | No GitHub Actions or GitLab CI config | Full pipeline: build, test, security scan, deploy | P1 |
| G-08 | No Helm chart | Raw K8s manifests in `infra/k8s/` | Helm chart with values.yaml for parameterized deploy | P1 |
| G-09 | No fleet management | No Rancher Fleet or GitOps | fleet.yaml for multi-cluster PoP deployment | P1 |
| G-10 | No log aggregation backend | Wazuh only (SIEM-specific) | Quickwit for general log search and analytics | P1 |

### 4.2 Security Gaps

| ID | Gap | Current State | Required State |
|----|-----|---------------|----------------|
| S-01 | Hardcoded default passwords | `.env.example` with `changeme_*` values | Secret management via HashiCorp Vault or K8s secrets |
| S-02 | No mTLS between microservices | Plain HTTP between portal and backend services | Service mesh mTLS (Cilium or Istio) |
| S-03 | No WAF | No web application firewall | ModSecurity or cloud WAF in front of portal |
| S-04 | No DDoS protection at edge | Only Suricata IPS | sase-ddos crate with XDP-based rate limiting |
| S-05 | RBI browser isolation incomplete | Dockerfile exists but not integrated | Full RBI pipeline with Chromium sandboxing |
| S-06 | No audit logging for control plane | No structured audit trail | Append-only audit log with tamper detection |

### 4.3 Performance Gaps

| ID | Gap | Current State | Target |
|----|-----|---------------|--------|
| P-01 | VPP integration incomplete | Scripts exist in `opensase-core/vpp/` but not wired to Rust crates | VPP + DPDK data plane at 100 Gbps |
| P-02 | XDP classifier not loaded | `bpf/xdp_classifier.c` exists but manual attach only | Automated XDP program management via Aya |
| P-03 | No ClickHouse for analytics | Prometheus only (limited query capability) | ClickHouse for time-series analytics at scale |
| P-04 | No connection pooling | New HTTP clients created per request in FastAPI backend | Connection pool with deadpool or bb8 |
| P-05 | No edge-side caching | No local policy cache on edge appliances | Edge-local DragonflyDB or embedded cache |

### 4.4 Feature Gaps

| ID | Gap | Current State | Required |
|----|-----|---------------|----------|
| F-01 | SWG (Secure Web Gateway) | Basic Suricata IPS + Unbound DNS | Full URL filtering, SSL inspection, content categorization |
| F-02 | FWaaS (Firewall as a Service) | nftables in security-pop container | Cloud-hosted firewall with per-tenant rule sets |
| F-03 | CASB | Python CASB-lite prototype | Full API-based and inline CASB with OAuth token vault |
| F-04 | DLP | Python DLP-lite with regex classifiers | ML-augmented DLP with exact data matching, OCR |
| F-05 | Email Security | Architecture doc exists, no implementation | MTA integration, attachment sandboxing |
| F-06 | SD-WAN path optimization | QoE selector prototype (Python) | Rust-native path selection in sase-path crate |
| F-07 | Multi-cloud connector | sase-cloud-connector crate scaffold | AWS, Azure, GCP VPC attachment |
| F-08 | Mobile clients | Scaffold files for iOS/Android | Full VPN client with WireGuard + ZTNA |
| F-09 | Desktop client (Tauri) | No Tauri project | Tauri 2.0 desktop app for Windows/macOS/Linux |

### 4.5 Operational Gaps

| ID | Gap | Description |
|----|-----|-------------|
| O-01 | No health dashboard aggregation | Individual service health checks but no unified view |
| O-02 | No automated backup/restore | No backup strategy for MongoDB, PostgreSQL, Wazuh data |
| O-03 | No capacity planning tools | No resource usage forecasting |
| O-04 | No runbook automation | Runbook docs exist but not automated |
| O-05 | No chaos testing | No fault injection framework |

## 5. Documentation Gaps

| ID | Gap | Current | Required |
|----|-----|---------|----------|
| D-01 | No PRD/BRD | README only | Full product and business requirements |
| D-02 | No database schema doc | No formal schema | ER diagrams, migration strategy |
| D-03 | No user manuals | No end-user docs | Admin, end-user, developer guides |
| D-04 | No training materials | None | Training manuals and video scripts |
| D-05 | No acceptance criteria | None | Testable acceptance criteria per feature |
| D-06 | No release notes | None | Versioned changelog |

## 6. Tech Stack Migration Needs

### Current Stack
- MongoDB 6 (FlexiWAN only)
- PostgreSQL 15 (Keycloak only)
- Prometheus + Grafana (observability)
- Wazuh/OpenSearch (SIEM)

### Target Stack (additions)
| Component | Purpose | Replaces |
|-----------|---------|----------|
| YugabyteDB | Distributed SQL for tenants, policies, sites | In-memory state |
| ScyllaDB | High-throughput NoSQL for sessions, flows | None |
| DragonflyDB | Redis-compatible cache | None |
| Redpanda | Event streaming (Kafka API compatible) | Direct HTTP |
| NATS JetStream | Lightweight pub/sub for control plane | None |
| Quickwit | Log search and analytics | None (Wazuh remains for SIEM) |
| ClickHouse | Time-series analytics | Prometheus long-term |
| OTel Collector | Telemetry pipeline | Direct Prometheus scrape |

## 7. Prioritized Remediation Roadmap

### Phase 1 (Weeks 1-4): Foundation
- [ ] Deploy YugabyteDB and migrate portal state
- [ ] Deploy DragonflyDB for session/policy caching
- [ ] Deploy Redpanda for event streaming
- [ ] Consolidate portal backend on Rust/Axum
- [ ] Add TLS termination via Caddy or cert-manager
- [ ] Create Helm chart from K8s manifests

### Phase 2 (Weeks 5-8): Security Hardening
- [ ] Implement mTLS between all microservices
- [ ] Integrate HashiCorp Vault for secret management
- [ ] Complete sase-ddos XDP-based DDoS mitigation
- [ ] Implement audit logging with append-only storage
- [ ] Complete RBI integration

### Phase 3 (Weeks 9-12): Feature Completion
- [ ] Complete SWG with URL categorization
- [ ] Implement FWaaS with per-tenant rules
- [ ] Upgrade CASB from Python prototype to Rust crate
- [ ] Upgrade DLP with ML classifiers
- [ ] Complete mobile clients (iOS, Android)

### Phase 4 (Weeks 13-16): Scale and Operations
- [ ] VPP + DPDK data plane integration
- [ ] Multi-cloud connector (AWS, Azure, GCP)
- [ ] ClickHouse analytics pipeline
- [ ] Chaos testing framework
- [ ] Automated backup/restore

## 8. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Dual portal backends cause maintenance burden | High | Medium | Consolidate on Rust Axum in Phase 1 |
| 45 Rust crates with incomplete src | High | High | Prioritize core crates (policy, dataplane, gateway) |
| FlexiWAN dependency for SD-WAN | Medium | High | Parallel development of native sase-sdwan crate |
| Performance targets (100 Gbps) may require hardware | Medium | Medium | Validate with TRex benchmarks in Phase 4 |
| Multi-tenancy retrofit is complex | Medium | High | Design tenant isolation from the start in Phase 1 |

## 9. Appendix: File Inventory

Total source files analyzed: 200+
- Rust source files (.rs): 85+
- Python source files (.py): 20+
- TypeScript/JavaScript (.ts/.tsx/.js): 15+
- YAML/TOML configuration: 40+
- Shell scripts (.sh): 20+
- Dockerfiles: 5
- Kubernetes manifests: 10+
- Documentation (.md): 45+
