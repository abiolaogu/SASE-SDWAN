# OpenSASE Core

**Ultra-High Performance SASE Platform in Pure Rust**

Target: 1000x faster than Python, sub-microsecond latency

## Performance Targets

| Component | Target Latency | Target Throughput |
|-----------|---------------|-------------------|
| Policy Lookup | <1μs P99 | 10M decisions/sec |
| Path Decision | <5μs P99 | 1M decisions/sec |
| DLP Scan | <50μs/1KB | 10GB/s |
| Packet Processing | <1μs | 10M+ pps |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     INNOVATION LAYER                             │
│  AI Path Prediction │ Behavioral Zero Trust │ Auto Remediation  │
└────────────────────────────────┬────────────────────────────────┘
                                 │
┌────────────────────────────────┴────────────────────────────────┐
│                     RUST CORE (100% Native)                      │
│                                                                  │
│  sase-policy    sase-path    sase-dlp    sase-casb              │
│  └─ <1μs        └─ <5μs      └─ <50μs    └─ <10μs              │
│                                                                  │
└────────────────────────────────┬────────────────────────────────┘
                                 │
┌────────────────────────────────┴────────────────────────────────┐
│                     KERNEL ACCELERATION                          │
│                                                                  │
│  eBPF/XDP        AF_XDP          io_uring                       │
│  └─ 100Gbps      └─ Zero-copy    └─ 10M IOPS                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Description | Status |
|-------|-------------|--------|
| `sase-common` | Shared types, zero-copy primitives | ✅ |
| `sase-policy` | Ultra-fast policy engine | ✅ |
| `sase-dlp` | 10GB/s content scanning | ✅ |
| `sase-path` | QoE-based path selection | 🚧 |
| `sase-casb` | Event processing | 🚧 |
| `sase-xdp` | eBPF/XDP integration | 🚧 |
| `sase-ml` | ML inference engine | 🚧 |
| `sase-behavioral` | Behavioral analytics | 🚧 |
| `sase-gateway` | Unified API gateway | 🚧 |

## Quick Start

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

## Key Technologies

### Lock-Free Data Structures
- `arc-swap` for atomic pointer swaps
- `dashmap` for concurrent hash maps
- `moka` for high-performance LRU cache

### Pattern Matching
- `aho-corasick` for O(n) multi-pattern matching
- `regex` with precompiled patterns
- Bloom filters for fast negative lookups

### Zero-Copy Networking
- eBPF/XDP for kernel-bypass packet processing
- AF_XDP for user-space fast path
- io_uring for async I/O

### Memory Efficiency
- Cache-line aligned structures (64 bytes)
- Object pooling for allocation-free paths
- SIMD-accelerated operations

## Benchmarks

```bash
# Policy lookup benchmark
cargo bench --bench policy_lookup

# DLP scan benchmark
cargo bench --bench dlp_scan
```

Expected results:
```
policy_lookup/cached    time: [45.2 ns 46.1 ns 47.0 ns]
policy_lookup/miss      time: [421 ns 432 ns 445 ns]
dlp_scan/1kb           time: [42.3 μs 44.1 μs 46.2 μs]
dlp_scan/1mb           time: [892 μs 914 μs 938 μs]
```

## XDP/eBPF

Compile eBPF programs:

```bash
# Requires clang and bpf headers
clang -O2 -target bpf -c bpf/xdp_classifier.c -o xdp_classifier.o
```

Load XDP program:

```bash
# Attach to interface
ip link set dev eth0 xdp obj xdp_classifier.o sec xdp
```

## License

Apache-2.0 OR GPL-2.0 (for eBPF components)
