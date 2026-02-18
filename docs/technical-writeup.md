# Technical Writeup -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Why This Architecture

### 1.1 Why Rust for the Data Plane

The decision to build the core data plane in Rust (100% of `opensase-core/`) is driven by three requirements that eliminate most alternatives:

1. **Sub-microsecond policy evaluation**: Python achieves ~10ms per policy lookup. Go achieves ~1ms. Rust with lock-free structures achieves ~46ns (cached) to ~432ns (miss). This is verified by `opensase-core/benches/policy_lookup.rs`.

2. **Memory safety without garbage collection**: GC pauses are unacceptable in packet processing. A 10ms GC pause at 100 Gbps means 125MB of buffered packets. Rust's ownership model provides memory safety with zero GC overhead.

3. **Zero-copy networking**: The eBPF/XDP integration (`opensase-core/bpf/`) requires C-compatible memory layouts. Rust's `#[repr(C)]` and `rkyv` zero-copy deserialization enable sharing memory between XDP programs and user space without copies.

### 1.2 Why VPP/DPDK Over Kernel Networking

Kernel networking on Linux achieves ~10 Gbps with optimization. VPP/DPDK bypasses the kernel entirely:

| Approach | Throughput | Latency | Complexity |
|----------|-----------|---------|------------|
| Linux kernel stack | ~10 Gbps | ~50us | Low |
| DPDK poll-mode | ~100 Gbps | ~5us | High |
| VPP on DPDK | ~100 Gbps | ~5us | Medium |
| XDP (eBPF) | ~100 Gbps (drop) | ~1us | Medium |

VPP provides a graph-based packet processing framework on top of DPDK, reducing development complexity while maintaining performance. The `sase-vpp` crate wraps VPP's C API, and `vpp-gateway` exposes it via gRPC for Kubernetes integration.

### 1.3 Why eBPF/XDP for DDoS Mitigation

XDP programs execute before the kernel network stack, at the NIC driver level. This means:
- DDoS packets are dropped at line rate (100 Gbps) without consuming CPU
- No memory allocation per packet
- No context switches
- The `bpf/xdp_classifier.c` program can process 14.88 Mpps (64-byte packets at 10 GbE)

### 1.4 Why Aho-Corasick for DLP

The `sase-dlp` crate uses Aho-Corasick (`aho-corasick` 1.1) for content scanning because:
- Scans for ALL patterns simultaneously in O(n) time (n = content length)
- Adding more patterns does not increase scan time (unlike sequential regex)
- SIMD-accelerated implementation in the Rust crate
- Combined with `memchr` 2.7 for fast byte scanning

## 2. Performance Trade-offs

### 2.1 Lock-Free vs Locked Data Structures

| Structure | Read Latency | Write Latency | Trade-off |
|-----------|-------------|---------------|-----------|
| `dashmap` (concurrent) | ~30ns | ~50ns | Higher memory from sharding |
| `arc-swap` (atomic swap) | ~10ns | ~100ns | Stale reads during swap window |
| `flurry` (lock-free) | ~25ns | ~80ns | Complex memory reclamation |
| `parking_lot::RwLock` | ~15ns read | ~40ns write | Writer starvation possible |
| `evmap` (eventual consistent) | ~10ns | ~200ns | Reads may be stale by 1 epoch |

OpenSASE uses `arc-swap` for policy hot-reload (read-optimized), `dashmap` for session tables (balanced), and `moka` for LRU caches (with TTL).

### 2.2 Serialization Performance

| Format | Serialize 1KB | Deserialize 1KB | Zero-Copy |
|--------|--------------|-----------------|-----------|
| `serde_json` | ~2us | ~3us | No |
| `simd-json` | ~1us | ~1.5us | Partial |
| `rkyv` | ~0.5us | ~0.1us | Yes |
| `bincode` | ~0.8us | ~0.6us | No |

OpenSASE uses `simd-json` 0.13 for external API responses and `rkyv` 0.7 for internal message passing where zero-copy deserialization matters.

### 2.3 ML Inference Latency

| Model | Framework | Latency (P50) | Latency (P99) | Throughput |
|-------|-----------|--------------|---------------|------------|
| DNS Detector (RF) | ONNX Runtime | 0.2ms | 0.8ms | 5K/sec/core |
| Network Anomaly (IF) | ONNX Runtime | 0.3ms | 1.0ms | 3K/sec/core |
| UBA (LSTM) | Candle | 0.5ms | 2.0ms | 2K/sec/core |
| Malware (GBT) | ONNX Runtime | 0.1ms | 0.5ms | 10K/sec/core |

ONNX Runtime (`ort` 2.0) is used for tree-based models; Candle (`candle-core` 0.3) for neural networks that benefit from GPU acceleration.

## 3. Protocol Choices

### 3.1 WireGuard Over IPsec

| Feature | WireGuard | IPsec (IKEv2) |
|---------|-----------|---------------|
| Codebase size | ~4,000 lines | ~400,000 lines |
| Handshake | 1-RTT (Noise protocol) | 2-RTT minimum |
| Cipher | ChaCha20-Poly1305 | AES-256-GCM (hardware) |
| Key exchange | X25519 | DH groups |
| Roaming | Built-in | Complex |
| Performance | ~8 Gbps (single core) | ~5 Gbps (single core) |
| Attack surface | Minimal | Large (many RFCs) |

OpenSASE chose WireGuard for its simplicity and performance. The `edge/src/tunnel.rs` uses `x25519-dalek` for key exchange, matching WireGuard's Noise_IK handshake.

### 3.2 gRPC Over REST for Internal Communication

VPP Gateway uses gRPC (Tonic 0.11) because:
- Binary serialization (protobuf) is 5-10x smaller than JSON
- Bidirectional streaming for real-time flow data
- Strong typing with generated code
- HTTP/2 multiplexing for concurrent RPCs

REST (Axum 0.7) is used for external APIs because:
- Better developer experience
- Easier debugging (curl, browser)
- OpenAPI documentation (utoipa)
- Wider SDK ecosystem

### 3.3 Redpanda Over Apache Kafka

| Feature | Redpanda | Apache Kafka |
|---------|----------|-------------|
| Language | C++ | Java/Scala |
| JVM required | No | Yes |
| Tail latency (P99) | < 10ms | ~50ms |
| Memory usage | ~500MB | ~4GB |
| Kafka API compatible | Yes | N/A |
| Tiered storage | Built-in | Plugin |

Redpanda provides Kafka API compatibility with 5-10x lower tail latency and significantly lower resource usage, critical for SASE edge deployments.

## 4. Architectural Decisions and Trade-offs

### 4.1 Monorepo vs Polyrepo

**Decision**: Monorepo (Cargo workspace)
**Trade-off**: Longer initial compile times (~5 min full build) but atomic cross-crate refactoring, shared dependency versions, and simplified CI/CD.

### 4.2 Dual Portal Backends

**Current state**: Both Python/FastAPI (`portal/backend/app/main.py`) and Rust/Axum (`portal/backend/src/main.rs`) exist.
**Trade-off**: Python is faster to prototype but adds a runtime dependency. Rust provides consistent performance and type safety.
**Decision**: Consolidate on Rust in production. Keep Python for lab demos where rapid iteration matters.

### 4.3 FlexiWAN Dependency

**Current state**: SD-WAN relies on FlexiWAN (AGPL-3.0) for controller and edge routers.
**Trade-off**: FlexiWAN provides mature SD-WAN features but creates vendor dependency and license restrictions.
**Decision**: Parallel development of native `sase-sdwan` crate. FlexiWAN remains for lab use. Production will use native implementation.

### 4.4 OpenZiti Dependency

**Current state**: ZTNA relies on OpenZiti (Apache-2.0).
**Trade-off**: OpenZiti provides battle-tested zero-trust networking but adds external dependency.
**Decision**: Keep OpenZiti integration. Develop native `sase-ztna` crate as an alternative for embedded use cases.

## 5. Scalability Analysis

### 5.1 Horizontal Scaling Bottlenecks

| Component | Bottleneck | Mitigation |
|-----------|-----------|------------|
| Policy Engine | Memory (policy set size) | Partition policies by tenant |
| DLP Engine | CPU (pattern matching) | Scale across cores, SIMD |
| VPP | NIC bandwidth | Multiple 100G NICs, LACP |
| YugabyteDB | Tablet splits | Pre-split by tenant_id |
| Redpanda | Partition count | Topic partitioning by PoP |

### 5.2 Vertical Scaling Limits

- Single VPP instance: ~100 Gbps (limited by NIC)
- Single Rust API server: ~100K req/sec (limited by CPU)
- Single PoP: ~500K concurrent sessions (limited by memory)

## 6. Security Design Rationale

### 6.1 Why Zero Trust Everywhere

Traditional perimeter security fails because:
- 40% of breaches originate from inside the network
- Cloud and remote work dissolve the perimeter
- Lateral movement is the primary attack progression

OpenSASE implements NIST 800-207 zero trust: verify explicitly, use least privilege, assume breach. Every session is authenticated and authorized, regardless of network location.

### 6.2 Why mTLS for Service Mesh

All inter-service communication uses mTLS (via Cilium or OpenZiti) because:
- Prevents eavesdropping on internal traffic
- Provides service identity verification
- Enables fine-grained authorization policies
- Required for SOC 2 Type II compliance

## 7. Future Architecture Considerations

1. **WebAssembly plugins**: Allow customers to write custom inspection logic in Wasm, running in a sandboxed environment within VPP.
2. **Tauri 2.0 desktop client**: Replace Electron-based clients with Tauri for 10x smaller binary size and native Rust integration with `client/core/`.
3. **eBPF CO-RE**: Compile-once-run-everywhere eBPF programs to eliminate kernel version dependencies.
4. **Hardware offload**: Leverage SmartNIC (Bluefield/Pensando) for policy evaluation in hardware.
