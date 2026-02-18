# Low-Level Design -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Packet Processing Pipeline

### 1.1 XDP Classifier (`opensase-core/bpf/xdp_classifier.c`)

The XDP program runs at the NIC driver level (before kernel network stack):

```c
// Simplified flow from bpf/xdp_classifier.c
SEC("xdp")
int xdp_classify(struct xdp_md *ctx) {
    // 1. Parse Ethernet header
    // 2. Parse IP header (v4/v6)
    // 3. Check DDoS rate limits (per-source-IP counter in BPF map)
    // 4. Lookup flow in known-good table (BPF hash map)
    // 5. If known-good: XDP_PASS to VPP fast path
    // 6. If unknown: XDP_REDIRECT to user-space slow path
    // 7. If blocked: XDP_DROP
}
```

BPF maps from `bpf/maps.h`:
- `flow_table`: Hash map of known flows (5-tuple -> action)
- `rate_limits`: Per-IP packet counters for DDoS mitigation
- `stats`: Per-CPU array for packet/byte counters

### 1.2 VPP Forwarding Engine

From `opensase-core/crates/sase-vpp/` and `vpp-gateway/`:

```
NIC (AF_XDP) -> VPP Input Node -> Classify Node -> Policy Lookup
    -> DLP Inspection Node -> IPS Inspection Node
    -> WireGuard Encrypt Node -> Output Node -> NIC
```

VPP graph nodes are connected in a directed acyclic graph. Each node processes a vector of packets (256 at a time) for cache efficiency.

Configuration: `vpp/scripts/setup_hugepages.sh` allocates 2MB hugepages for DPDK memory pools.

### 1.3 VPP Gateway gRPC Interface

From `opensase-core/crates/vpp-gateway/`:
- Connects to VPP via Unix domain socket (`/run/vpp/cli.sock`)
- Exposes gRPC service on port 50052
- Provides: `GetStats`, `UpdatePolicy`, `AddTunnel`, `RemoveTunnel`
- Build script (`build.rs`) generates protobuf bindings

## 2. Policy Engine Internals

### 2.1 Data Structures

From `opensase-core/crates/sase-policy/`:

```rust
// Policy lookup using arc-swap for hot reload
pub struct PolicyEngine {
    // Active policy set (atomically swappable)
    policies: arc_swap::ArcSwap<PolicySet>,
    // Cache for recent lookups
    cache: moka::future::Cache<PolicyKey, PolicyDecision>,
    // Bloom filter for fast negative lookup
    bloom: parking_lot::RwLock<BloomFilter>,
}

// Cache-line aligned for performance (64 bytes)
#[repr(align(64))]
pub struct PolicyKey {
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    tenant_id: u32,
    _padding: [u8; 43],
}
```

### 2.2 Lookup Algorithm

1. Hash the 5-tuple + tenant_id
2. Check Bloom filter (fast negative: if absent, definitely no match)
3. Check Moka cache (L1, ~46ns)
4. If cache miss: lookup in DashMap policy table (~432ns)
5. Cache result in Moka
6. Return PolicyDecision: Allow, Block, Isolate, or Log

Benchmark results from `opensase-core/benches/policy_lookup.rs`:
```
policy_lookup/cached  [45.2 ns 46.1 ns 47.0 ns]
policy_lookup/miss    [421 ns  432 ns  445 ns]
```

## 3. DLP Engine Internals

### 3.1 Pattern Matching

From `opensase-core/crates/sase-dlp/` and `components/dlp-lite/dlp_lite/scanner.py`:

The Rust implementation uses `aho-corasick` for simultaneous multi-pattern matching:
```rust
pub struct DlpEngine {
    // Aho-Corasick automaton for all patterns
    automaton: aho_corasick::AhoCorasick,
    // Compiled regex patterns for complex rules
    regexes: Vec<regex::Regex>,
    // SIMD-accelerated JSON parser for structured data
    simd_parser: simd_json::Deserializer,
}
```

The Python implementation (`dlp_lite/scanner.py`) provides `ContentScanner`:
- Runs all classifiers (SSN, credit card, API keys)
- Deduplicates overlapping matches by position
- Returns `ScanResult` with highest severity

### 3.2 DLP Scan Pipeline

```
Input Content -> Tokenize -> Aho-Corasick (multi-pattern)
    -> Regex Validation (Luhn check for credit cards)
    -> SIMD-JSON parse (for structured data)
    -> Severity Classification
    -> Deduplicate Overlaps
    -> ScanResult
```

Target: 10 GB/s throughput, < 50us per 1KB content.

## 4. ML Inference Engine

### 4.1 Architecture

From `ml/inference/src/lib.rs`, the `ThreatEngine` contains four detector models:

| Detector | Model Type | Input | Output |
|----------|-----------|-------|--------|
| `DnsThreatDetector` | Random Forest + CNN | DNS query features | is_threat, confidence |
| `NetworkAnomalyDetector` | Isolation Forest + Autoencoder | Flow features | anomaly_score |
| `UbaDetector` | LSTM | User session history | risk_score |
| `MalwareDetector` | Gradient Boosted Trees | Traffic patterns | is_malware |

### 4.2 Feature Extraction

From `ml/inference/src/features.rs`:
```rust
pub struct DnsQuery {
    pub domain: String,
    pub query_type: u16,
    pub source_ip: std::net::IpAddr,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct FlowFeatures {
    pub source_ip: std::net::IpAddr,
    pub dest_ip: std::net::IpAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
    pub packet_count: u32,
}
```

### 4.3 Inference Pipeline

```
Flow/DNS/Session -> Feature Extraction (features.rs)
    -> Model Prediction (ONNX Runtime via ort crate)
    -> Threshold Check (configurable per model)
    -> Alert Generation (alerts.rs with MITRE mapping)
    -> Deduplication + Correlation
    -> Output to Wazuh + Portal WebSocket
```

Target: < 1ms latency, 10K flows/sec/core.

## 5. WireGuard Tunnel Implementation

### 5.1 Key Exchange

From `edge/src/tunnel.rs` using `x25519-dalek`:
```rust
pub struct TunnelManager {
    tunnels: DashMap<TunnelId, WireGuardTunnel>,
}

pub struct WireGuardTunnel {
    private_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,
    peer_public_key: x25519_dalek::PublicKey,
    preshared_key: Option<[u8; 32]>,
    endpoint: std::net::SocketAddr,
    keepalive_interval: std::time::Duration,
    mtu: u16,
}
```

### 5.2 Tunnel Lifecycle

1. Generate X25519 keypair
2. Exchange public keys with controller
3. Configure WireGuard interface
4. Set MTU (default 1420 from docker-compose.yml)
5. Enable keepalive (25 seconds)
6. Monitor tunnel health via `health.rs`

### 5.3 Path Selection

From `edge/src/sdwan.rs` and `components/qoe-selector/`:
- Per-application class thresholds from `qoe_selector/models.py`:
  - Voice: max 30ms latency, 10ms jitter, 1% loss (weight: latency 0.4, jitter 0.2, loss 0.3)
  - Video: max 100ms latency, 30ms jitter, 2% loss
  - Web: max 200ms latency, 50ms jitter, 5% loss
  - Bulk: max 500ms latency, 100ms jitter, 10% loss

## 6. Edge Appliance Internals

### 6.1 Component Architecture

From `edge/src/lib.rs`:

```rust
pub struct OpenSASEEdge {
    pub config: Arc<RwLock<EdgeConfig>>,       // parking_lot RwLock
    pub interfaces: Arc<InterfaceManager>,      // network.rs
    pub sdwan: Arc<SdwanController>,           // sdwan.rs
    pub security: Arc<SecurityStack>,           // security.rs
    pub tunnels: Arc<TunnelManager>,           // tunnel.rs
    state: Arc<RwLock<EdgeState>>,             // Initializing|Running|Degraded|Error|Shutdown
}
```

### 6.2 Initialization Sequence

```
1. Load EdgeConfig from /etc/opensase/edge.json (config.rs)
2. Configure WAN/LAN interfaces (network.rs)
3. Register with controller via HTTPS (ztp.rs)
4. Establish WireGuard tunnels to all configured PoPs (tunnel.rs)
5. Initialize local security stack (security.rs)
6. Start SD-WAN path selection (sdwan.rs)
7. Start local API server on :9443 (api.rs)
8. Start health monitoring loop (health.rs)
9. Start metrics exporter (metrics.rs)
10. Set state to Running
```

### 6.3 API Endpoints

From `edge/src/api.rs`:
- `GET /health` -- Edge health status
- `GET /interfaces` -- WAN/LAN interface status
- `GET /tunnels` -- Active tunnel information
- `GET /routing` -- Current routing table
- `GET /metrics` -- Prometheus metrics
- `POST /config` -- Apply configuration update

## 7. Portal Backend Internals

### 7.1 Rust Backend (Production)

From `portal/backend/src/main.rs`:
```rust
pub struct AppState {
    pub sites: Arc<RwLock<Vec<models::Site>>>,
    pub users: Arc<RwLock<Vec<models::User>>>,
    pub apps: Arc<RwLock<Vec<models::App>>>,
    pub policies: Arc<RwLock<Vec<models::Policy>>>,
}
```

Routes: sites CRUD, users CRUD, apps CRUD, policies CRUD, analytics (overview/traffic/security), WebSocket at `/ws`.

### 7.2 Python Backend (Lab/Demo)

From `portal/backend/app/main.py`:
- Aggregates data from FlexiWAN, OpenZiti, Wazuh, Security PoP
- `check_service_health()` probes each backend
- Falls back to simulated data when backends unavailable

## 8. Frontend Component Architecture

### 8.1 React Application

From `opensase-portal/src/App.tsx`:
```
Routes:
/            -> Dashboard.tsx (traffic charts, alerts, device status)
/sites       -> Sites.tsx (site management)
/tunnels     -> Tunnels.tsx (tunnel management)
/policies    -> Policies.tsx (policy editor)
/security    -> Security.tsx (threat dashboard)
/settings    -> Settings.tsx (configuration)
```

### 8.2 Dashboard Components

From `opensase-portal/src/pages/Dashboard.tsx`:
- Stats grid: Active Sites (12), Active Tunnels (24), Throughput (87.2 Gbps), Threats Blocked (1,247)
- Traffic chart: Recharts AreaChart with ingress/egress
- Alerts list: severity-colored items with site and time
- Device table: name, type, status badge, tunnels, last seen

## 9. Security Implementation Details

### 9.1 JWT Authentication

From `api/src/middleware/auth.rs`:
- Validates JWT tokens from Keycloak
- Extracts tenant_id and role from claims
- Supports both Bearer tokens and API keys

### 9.2 Rate Limiting

From `api/src/middleware/rate_limit.rs`:
- Per-tenant rate limits (from OpenAPI spec: Free=60/min, Pro=600/min, Enterprise=6000/min)
- Token bucket algorithm
- Headers: `X-RateLimit-Remaining`, `X-RateLimit-Reset`

### 9.3 Webhook Security

From `api/src/webhooks.rs`:
- HMAC-SHA256 signature verification
- Retry with exponential backoff
- Event types: `policy.updated`, `site.status_changed`, `alert.created`, `tunnel.status_changed`

## 10. Configuration File Formats

### 10.1 Edge Config (`/etc/opensase/edge.json`)

```json
{
    "device_name": "branch-a",
    "controller_url": "https://api.opensase.io",
    "pop_connections": [
        {"endpoint": "pop-nyc.opensase.io:51820", "public_key": "..."}
    ],
    "interfaces": {
        "wan1": {"dhcp": true, "metric": 10},
        "wan2": {"dhcp": true, "metric": 20},
        "lte": {"apn": "internet", "metric": 100},
        "lan": {"ip": "10.0.0.1/24"}
    }
}
```

### 10.2 UPO Intent Policy (`components/upo/sample_policies/corporate-access.yaml`)

```yaml
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
segments:
  - name: corporate
    vlan: 100
    vrf_id: 1
access_rules:
  - name: allow-engineering-gitlab
    users: [engineering]
    apps: [gitlab]
    action: allow
    priority: 10
```
