# Software Requirements -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Runtime Dependencies

### 1.1 Container Runtime
| Software | Version | Purpose |
|----------|---------|---------|
| Docker Engine | 24.0+ | Container runtime |
| Docker Compose | V2 (bundled) | Local orchestration |
| containerd | 1.7+ | Kubernetes CRI |

### 1.2 Kubernetes Stack
| Software | Version | Purpose |
|----------|---------|---------|
| Kubernetes | 1.29+ | Container orchestration |
| Talos Linux | 1.6+ | Immutable OS for K8s nodes |
| Cilium | 1.15+ | CNI, service mesh, L7 policies |
| Helm | 3.14+ | Package management |
| Rancher Fleet | 0.9+ | GitOps multi-cluster management |

### 1.3 Operating Systems
| OS | Version | Use |
|----|---------|-----|
| Ubuntu | 22.04 LTS | Development, edge appliance |
| Debian | Bookworm (12) | Edge appliance, containers |
| Alpine | 3.19 | Minimal containers |
| Talos Linux | 1.6+ | Production K8s nodes |
| macOS | 14+ (Sonoma) | Development workstation |

## 2. Build Dependencies

### 2.1 Rust Toolchain
| Tool | Version | Purpose |
|------|---------|---------|
| rustc | 1.75+ (2021 edition) | Compiler |
| cargo | 1.75+ | Build system |
| rustfmt | Latest | Code formatting |
| clippy | Latest | Linting |
| cargo-criterion | 0.5+ | Benchmarking |

### 2.2 Node.js Toolchain (Portal Frontend)
| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | 20 LTS | JavaScript runtime |
| npm | 10+ | Package manager |
| Vite | 5.0+ | Build tool |
| TypeScript | 5.3+ | Type checking |
| ESLint | 8.56+ | Linting |

### 2.3 Python Toolchain (Components)
| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.11+ | Runtime for UPO, QoE, CASB, DLP |
| pip | 23+ | Package manager |
| Pydantic | 2.0+ | Data validation |
| FastAPI | 0.100+ | API framework |
| pytest | 7.0+ | Testing |

### 2.4 eBPF Build Tools
| Tool | Version | Purpose |
|------|---------|---------|
| clang | 15+ | BPF program compiler |
| llvm | 15+ | BPF backend |
| bpftool | 7.0+ | BPF program management |
| libbpf-dev | 1.0+ | BPF development headers |
| Linux kernel headers | 5.15+ | BTF support required |

## 3. Third-Party Services (Docker Compose)

From `docker-compose.yml`:

| Service | Image | Version | Port |
|---------|-------|---------|------|
| FlexiWAN Controller | `flexiwan/flexiwan:latest` | Latest | 3000, 4433 |
| FlexiWAN Router | `flexiwan/flexiwan-router:latest` | Latest | - |
| MongoDB | `mongo:6` | 6.x | 27017 |
| OpenZiti Controller | `openziti/ziti-controller:latest` | Latest | 1280 |
| OpenZiti Router | `openziti/ziti-router:latest` | Latest | 3022 |
| Wazuh Indexer | `wazuh/wazuh-indexer:4.7.0` | 4.7.0 | 9200 |
| Wazuh Manager | `wazuh/wazuh-manager:4.7.0` | 4.7.0 | 1514, 1515, 55000 |
| Wazuh Dashboard | `wazuh/wazuh-dashboard:4.7.0` | 4.7.0 | 5601 |
| Keycloak | `quay.io/keycloak/keycloak:23.0` | 23.0 | 8080 |
| PostgreSQL | `postgres:15-alpine` | 15 | 5432 |
| Prometheus | `prom/prometheus:v2.48.0` | 2.48.0 | 9090 |
| Grafana | `grafana/grafana:10.2.0` | 10.2.0 | 3000 |
| Nginx | `nginx:alpine` | Alpine | 80 |
| HTTPBin | `kennethreitz/httpbin` | Latest | 80 |

## 4. Target Database Stack

| Database | Version | Purpose | Protocol |
|----------|---------|---------|----------|
| YugabyteDB | 2.20+ | Distributed SQL | PostgreSQL wire protocol |
| ScyllaDB | 5.4+ | High-throughput NoSQL | CQL (Cassandra compatible) |
| DragonflyDB | 1.14+ | Cache layer | Redis protocol |
| ClickHouse | 24.1+ | Analytics OLAP | HTTP/Native |

## 5. Messaging Stack

| System | Version | Purpose | Protocol |
|--------|---------|---------|----------|
| Redpanda | 23.3+ | Event streaming | Kafka API |
| NATS JetStream | 2.10+ | Control plane pub/sub | NATS protocol |

## 6. Observability Stack

| Tool | Version | Purpose |
|------|---------|---------|
| Prometheus | 2.48+ | Metrics collection |
| Grafana | 10.2+ | Dashboard visualization |
| Quickwit | 0.7+ | Log search engine |
| OpenTelemetry Collector | 0.92+ | Telemetry pipeline |

## 7. Rust Crate Dependencies

From `opensase-core/Cargo.toml` workspace:

| Category | Crate | Version | Purpose |
|----------|-------|---------|---------|
| Async | tokio | 1.35 | Async runtime |
| Async | async-trait | 0.1 | Async trait support |
| Concurrency | dashmap | 5.5 | Concurrent hash map |
| Concurrency | arc-swap | 1.6 | Atomic pointer swap |
| Concurrency | crossbeam | 0.8 | Lock-free utilities |
| Concurrency | parking_lot | 0.12 | Fast mutex/rwlock |
| Cache | moka | 0.12 | Async-aware LRU cache |
| Serialization | serde | 1.0 | Serialization framework |
| Serialization | serde_json | 1.0 | JSON |
| Serialization | simd-json | 0.13 | SIMD-accelerated JSON |
| Serialization | rkyv | 0.7 | Zero-copy deserialization |
| Pattern Match | aho-corasick | 1.1 | Multi-pattern matching |
| Pattern Match | regex | 1.10 | Regular expressions |
| Pattern Match | memchr | 2.7 | SIMD byte search |
| eBPF | aya | 0.12 | eBPF from Rust |
| eBPF | libbpf-rs | 0.22 | libbpf bindings |
| ML | ort | 2.0 | ONNX Runtime |
| ML | candle-core | 0.3 | ML framework |
| HTTP | axum | 0.7 | Web framework |
| gRPC | tonic | 0.11 | gRPC framework |
| HTTP | hyper | 1.1 | HTTP library |
| Observability | tracing | 0.1 | Structured logging |
| Observability | metrics | 0.22 | Metrics API |
| Crypto | sha2 | 0.10 | SHA-256 |
| Crypto | x25519-dalek | 2 | Key exchange |
| Testing | criterion | 0.5 | Benchmarking |
| Testing | proptest | 1.4 | Property testing |

## 8. Frontend Dependencies

From `opensase-portal/package.json`:

| Package | Version | Purpose |
|---------|---------|---------|
| react | 18.2 | UI framework |
| react-dom | 18.2 | DOM rendering |
| react-router-dom | 6.21 | Client-side routing |
| @tanstack/react-query | 5.17 | Server state management |
| axios | 1.6 | HTTP client |
| recharts | 2.10 | Chart library |
| lucide-react | 0.303 | Icon library |
| clsx | 2.1 | CSS class utility |
| date-fns | 3.2 | Date formatting |
| vite | 5.0 | Build tool |
| vitest | 1.1 | Test runner |
| typescript | 5.3 | Type system |

## 9. Python Dependencies

From `components/*/pyproject.toml`:

| Package | Version | Component |
|---------|---------|-----------|
| pydantic | 2.0+ | All components |
| fastapi | 0.100+ | UPO, QoE, CASB, DLP APIs |
| uvicorn | 0.24+ | ASGI server |
| httpx | 0.25+ | Async HTTP client |
| pyyaml | 6.0+ | YAML parsing (UPO) |
| pytest | 7.0+ | Testing |

## 10. Compatibility Matrix

| Platform | Rust Core | Portal | Edge | CLI | Docker Compose |
|----------|-----------|--------|------|-----|----------------|
| Linux x86_64 | Yes | Yes | Yes | Yes | Yes |
| Linux aarch64 | Yes | Yes | Yes | Yes | Yes |
| macOS x86_64 | Yes (dev) | Yes | No | Yes | Yes |
| macOS aarch64 | Yes (dev) | Yes | No | Yes | Yes |
| Windows x86_64 | Build only | Yes | No | Yes | WSL2 only |
