# OpenSASE Crate Reference

## Complete Crate Index (33 Crates, ~66,000 Lines Rust)

---

## Core Platform Crates

### sase-common
**Shared types and utilities**

```rust
// Key exports
pub struct TenantId(String);
pub struct SessionId(String);
pub enum Severity { Info, Low, Medium, High, Critical }
pub trait Hashable { fn hash(&self) -> String; }
```

### sase-policy
**Unified policy engine**

```rust
pub struct PolicyEngine {
    pub evaluate(&self, context: &PolicyContext) -> PolicyDecision;
    pub add_rule(&self, rule: PolicyRule);
}

pub enum PolicyAction { Allow, Deny, Challenge, Log }
```

### sase-tenant
**Multi-tenant management**

```rust
pub struct TenantManager {
    pub create_tenant(&self, config: TenantConfig) -> Tenant;
    pub get_tenant(&self, id: &TenantId) -> Option<Tenant>;
}

pub struct TenantConfig {
    pub name: String,
    pub subscription: SubscriptionTier,
    pub features: Vec<Feature>,
}
```

### sase-billing
**Usage metering and billing**

```rust
pub struct BillingEngine {
    pub record_usage(&self, tenant: &TenantId, metric: UsageMetric);
    pub generate_invoice(&self, tenant: &TenantId, period: Period) -> Invoice;
}
```

---

## Data Plane Crates

### sase-vpp
**VPP management API**

```rust
pub struct VppManager {
    pub configure_interface(&self, config: InterfaceConfig);
    pub add_acl(&self, acl: AclRule);
    pub create_wireguard_tunnel(&self, config: WgConfig) -> TunnelId;
    pub get_stats(&self) -> VppStats;
}
```

### sase-dataplane
**Packet processing pipeline**

```rust
pub struct DataplaneEngine {
    pub process_packet(&self, packet: &mut Packet) -> PacketAction;
}

pub enum PacketAction { Forward, Drop, Redirect, Inspect }
```

### sase-xdp
**XDP/eBPF programs**

```rust
pub struct XdpProgram {
    pub load(&self, interface: &str);
    pub update_map(&self, map: &str, key: &[u8], value: &[u8]);
}
```

### sase-ddos
**DDoS mitigation**

```rust
pub struct DdosEngine {
    pub detect_attack(&self, stats: &FlowStats) -> Option<Attack>;
    pub mitigate(&self, attack: &Attack) -> MitigationResult;
}

// Targets: 100+ Gbps volumetric, 50M+ PPS
```

---

## Security Services Crates

### sase-ips
**IPS with Hyperscan**

```rust
pub struct IpsEngine {
    pub load_rules(&self, rules: Vec<SuricataRule>);
    pub scan(&self, payload: &[u8]) -> Vec<Match>;
}

// 40+ Gbps scanning rate
```

### sase-dlp
**Data Loss Prevention**

```rust
pub struct DlpEngine {
    pub scan_content(&self, content: &Content) -> Vec<DlpMatch>;
    pub get_patterns(&self) -> Vec<DlpPattern>;
}

pub enum DlpPattern {
    CreditCard, SSN, Email, CustomRegex(String),
}
```

### sase-casb
**SaaS Security Broker**

```rust
pub struct CasbEngine {
    pub evaluate_saas_access(&self, app: &SaasApp, user: &User) -> AccessDecision;
    pub get_shadow_it(&self) -> Vec<SaasApp>;
}
```

### sase-email-security
**Email protection**

```rust
pub struct EmailGateway {
    pub process_inbound(&self, email: &Email) -> EmailVerdict;
    pub verify_spf(&self, email: &Email) -> SpfResult;
    pub verify_dkim(&self, email: &Email) -> DkimResult;
}
```

### sase-rbi
**Browser Isolation**

```rust
pub struct RbiEngine {
    pub create_session(&self, user: &User, url: &Url) -> RbiSession;
    pub render_page(&self, session: &RbiSession) -> PixelStream;
}
```

### sase-threat-intel
**IOC correlation**

```rust
pub struct ThreatIntelEngine {
    pub check_indicator(&self, indicator: &Indicator) -> Option<ThreatMatch>;
    pub update_feeds(&self);
}

// < 1μs lookup latency via Bloom filters
```

---

## Layer 7 Gateway Crates

### sase-gateway
**API Gateway**

```rust
pub struct ApiGateway {
    pub route(&self, request: &Request) -> Response;
    pub add_route(&self, route: Route);
}
```

### sase-l7
**L7 proxy backend**

```rust
pub struct L7Engine {
    pub inspect(&self, stream: &TlsStream) -> InspectionResult;
    pub apply_policy(&self, request: &HttpRequest) -> PolicyResult;
}
```

### sase-xds
**xDS control plane**

```rust
pub struct XdsServer {
    pub serve(&self, addr: SocketAddr);
    pub push_config(&self, cluster: &str, config: EnvoyConfig);
}
```

### sase-envoy-filters
**WASM filters**

```rust
// AuthZ Filter
// URL Filter
// DLP Filter
// CASB Filter
// Malware Filter
// Lua Filter
```

### sase-usie
**Unified Security Inspection**

```rust
pub struct UsieEngine {
    pub inspect(&self, traffic: &Traffic) -> InspectionResult;
}

// Single-pass inspection for all security checks
```

---

## Access Control Crates

### sase-ztna
**Zero Trust Access (17 modules)**

```rust
pub struct ZeroTrustGateway {
    pub request_access(&self, request: AccessRequest) -> AccessDecision;
}

pub struct TrustEvaluationEngine {
    pub evaluate(&self, context: &TrustContext) -> TrustScore;
}

// Modules: identity, authn, mfa, sso, device, context,
// policy, authz, risk, continuous, microseg, session,
// audit, trust_engine, posture, clientless, recording,
// microseg_enhanced, stepup
```

### sase-fpe
**Format-Preserving Encryption**

```rust
pub struct FpeEngine {
    pub encrypt(&self, plaintext: &str, format: Format) -> String;
    pub decrypt(&self, ciphertext: &str, format: Format) -> String;
}
```

---

## SD-WAN Crates

### sase-sdwan
**SD-WAN orchestration**

```rust
pub struct SdwanOrchestrator {
    pub enroll_site(&self, site: Site) -> SiteId;
    pub configure_tunnel(&self, site: &SiteId, config: TunnelConfig);
    pub get_path_stats(&self, site: &SiteId) -> PathStats;
}
```

### sase-path
**Path selection**

```rust
pub struct PathSelector {
    pub select_best_path(&self, dst: &Destination, sla: &Sla) -> Path;
    pub failover(&self, failed_path: &Path) -> Option<Path>;
}
```

### sase-resilience
**HA and failover**

```rust
pub struct ResilienceManager {
    pub configure_ha(&self, config: HaConfig);
    pub trigger_failover(&self, reason: FailoverReason);
}
```

---

## Intelligence Crates

### sase-ml
**ML inference**

```rust
pub struct MlEngine {
    pub load_model(&self, model: &OnnxModel);
    pub infer(&self, input: &Tensor) -> Tensor;
}
```

### sase-behavioral
**Behavioral analysis**

```rust
pub struct BehavioralEngine {
    pub analyze(&self, user: &User, activity: &Activity) -> AnomalyScore;
    pub update_baseline(&self, user: &User, activity: &Activity);
}
```

### sase-ite
**Traffic engineering**

```rust
pub struct TrafficEngine {
    pub optimize_path(&self, flow: &Flow) -> OptimalPath;
    pub balance_load(&self, destinations: &[Destination]) -> LoadDistribution;
}
```

---

## Infrastructure Crates

### sase-orchestrator
**PoP orchestration**

```rust
pub struct PopOrchestrator {
    pub deploy_pop(&self, config: PopConfig) -> PopId;
    pub scale_pop(&self, pop: &PopId, capacity: Capacity);
    pub get_pop_status(&self, pop: &PopId) -> PopStatus;
}
```

### sase-backbone
**Private backbone**

```rust
pub struct BackboneManager {
    pub configure_circuit(&self, circuit: Circuit);
    pub optimize_routing(&self);
    pub get_latency_matrix(&self) -> LatencyMatrix;
}
```

### sase-peering
**IXP peering**

```rust
pub struct PeeringManager {
    pub establish_session(&self, peer: BgpPeer) -> SessionId;
    pub get_routes(&self, session: &SessionId) -> Vec<Route>;
}
```

### sase-compliance
**Regulatory compliance**

```rust
pub struct ComplianceEngine {
    pub run_assessment(&self, framework: Framework) -> Assessment;
    pub generate_report(&self, framework: Framework) -> Report;
}
```

---

## SOC Operations Crate

### sase-soc (16 modules, ~6,500 lines)

```rust
// Core
pub struct SecurityOperationsPlatform { ... }
pub struct SecurityEvent { ... }
pub struct SecurityAlert { ... }

// SIEM Integration
pub struct SiemIntegration { ... }  // Splunk, Elastic, Sentinel, QRadar

// SOAR
pub struct SoarEngine { ... }
pub struct Playbook { ... }

// Case Management
pub struct CaseManager { ... }
pub struct Case { ... }

// Threat Hunting
pub struct ThreatHunter { ... }

// Forensics
pub struct ForensicsCollector { ... }

// Compliance
pub struct ComplianceEngine { ... }

// Pipeline
pub struct EventPipeline { ... }
pub struct EventNormalizer { ... }
pub struct EventEnricher { ... }
pub struct EventCorrelator { ... }

// EDR
pub trait EdrIntegration { ... }
pub struct CrowdStrikeEdr { ... }
pub struct DefenderEdr { ... }
pub struct SentinelOneEdr { ... }

// Metrics
pub struct SocMetrics { ... }
```

---

## Usage Example

```rust
use sase_ztna::ZeroTrustGateway;
use sase_policy::PolicyEngine;
use sase_soc::SecurityOperationsPlatform;

#[tokio::main]
async fn main() {
    // Initialize ZTNA
    let ztna = ZeroTrustGateway::new(ZtnaConfig::default());
    
    // Initialize SOC
    let soc = SecurityOperationsPlatform::new(SopConfig::default());
    
    // Process access request
    let decision = ztna.request_access(access_request).await;
    
    // Forward security event
    soc.ingest_event(security_event).await;
}
```
