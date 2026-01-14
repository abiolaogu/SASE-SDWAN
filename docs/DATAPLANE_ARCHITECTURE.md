# OpenSASE Data Plane Architecture

## Performance Targets

| Metric | Single Core | 4 Cores |
|--------|-------------|---------|
| Throughput | 10 Gbps | 40+ Gbps |
| Packet Rate | 14.8 Mpps | 60 Mpps |
| Latency | <25μs P99 | <50μs P99 |
| Memory | <4GB/1M flows | <16GB/4M flows |

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              USERSPACE                                      │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    FAST PATH ENGINE (FPE)                             │  │
│  │                                                                       │  │
│  │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌────────┐ │  │
│  │  │  Core 0 │   │  Core 1 │   │  Core 2 │   │  Core 3 │   │ Stats  │ │  │
│  │  │         │   │         │   │         │   │         │   │        │ │  │
│  │  │ ┌─────┐ │   │ ┌─────┐ │   │ ┌─────┐ │   │ ┌─────┐ │   │ atomic │ │  │
│  │  │ │ RX  │ │   │ │ RX  │ │   │ │ RX  │ │   │ │ RX  │ │   │        │ │  │
│  │  │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   └────────┘ │  │
│  │  │ │Parse│ │   │ │Parse│ │   │ │Parse│ │   │ │Parse│ │              │  │
│  │  │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   ┌────────┐ │  │
│  │  │ │Class│ │   │ │Class│ │   │ │Class│ │   │ │Class│ │   │ Crypto │ │  │
│  │  │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │        │ │  │
│  │  │ │ NAT │ │   │ │ NAT │ │   │ │ NAT │ │   │ │ NAT │ │   │ChaCha20│ │  │
│  │  │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │AES-GCM │ │  │
│  │  │ │Crypt│ │   │ │Crypt│ │   │ │Crypt│ │   │ │Crypt│ │   └────────┘ │  │
│  │  │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │              │  │
│  │  │ │Encap│ │   │ │Encap│ │   │ │Encap│ │   │ │Encap│ │   ┌────────┐ │  │
│  │  │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ Flow   │ │  │
│  │  │ │ QoS │ │   │ │ QoS │ │   │ │ QoS │ │   │ │ QoS │ │   │ Table  │ │  │
│  │  │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │ ├─────┤ │   │        │ │  │
│  │  │ │ TX  │ │   │ │ TX  │ │   │ │ TX  │ │   │ │ TX  │ │   │lockless│ │  │
│  │  │ └─────┘ │   │ └─────┘ │   │ └─────┘ │   │ └─────┘ │   │ 1M+    │ │  │
│  │  └─────────┘   └─────────┘   └─────────┘   └─────────┘   └────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              │ AF_XDP                                       │
└──────────────────────────────┼──────────────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────────────┐
│                              │ KERNEL                                       │
│  ┌───────────────────────────▼──────────────────────────────────────────┐  │
│  │                         XDP Program                                   │  │
│  │   • Early steering to AF_XDP                                         │  │
│  │   • Drop known-bad (DDoS mitigation)                                 │  │
│  │   • Pass ICMP/ARP to kernel stack                                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                       Slow Path (Kernel Stack)                        │  │
│  │   • First packet of flow (until classified)                          │  │
│  │   • ICMP errors                                                       │  │
│  │   • Exception packets                                                 │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Stages

### RX → Parse → Classify → NAT → Encrypt → Encap → QoS → TX

| Stage | Latency | Description |
|-------|---------|-------------|
| **RX** | <1μs | AF_XDP UMEM poll |
| **Parse** | <100ns | L2-L4 header extraction |
| **Classify** | <500ns | DPI + policy lookup |
| **NAT** | <200ns | SNAT/DNAT rewrite |
| **Encrypt** | <2μs | ChaCha20/AES-GCM |
| **Encap** | <300ns | VxLAN/GRE/Geneve |
| **QoS** | <100ns | DSCP mark + shaping |
| **TX** | <1μs | AF_XDP transmit |

---

## Flow Table Design

```
┌────────────────────────────────────────────┐
│            Lockless Flow Table             │
├────────────────────────────────────────────┤
│  • Open addressing + linear probing        │
│  • FNV-1a hash (5-tuple)                   │
│  • Atomic state transitions                │
│  • Per-entry RwLock (rare contention)      │
│  • 75% load factor                         │
│  • EWMA-based aging                        │
└────────────────────────────────────────────┘

Memory: 64 bytes/entry × 1M flows = 64MB per core
```

---

## Buffer Pool

```
┌────────────────────────────────────────────┐
│          Zero-Copy Buffer Pool             │
├────────────────────────────────────────────┤
│  • Hugepage-backed (2MB pages)             │
│  • 2KB buffers, cache-line aligned         │
│  • Lock-free alloc/free                    │
│  • Reference counting                      │
│  • Headroom for encapsulation (128B)       │
└────────────────────────────────────────────┘

Memory: 2KB × 64K buffers = 128MB per core
```

---

## Latency Breakdown (P99)

```
  0       5       10      15      20      25 μs
  │───────│───────│───────│───────│───────│
  ├─RX────┤                                   0.8μs
         ├─Parse─┤                            0.1μs
                ├─Classify──┤                 0.5μs
                           ├─NAT─┤            0.2μs
                               ├──Encrypt────┤ 2.0μs
                                         ├Encap┤ 0.3μs
                                            ├QoS┤ 0.1μs
                                              ├─TX──┤ 0.8μs
  │───────────────────────────────────────────│
                                         ~5μs total
```

---

## Files

| Path | Description |
|------|-------------|
| `src/core.rs` | Engine + workers |
| `src/flow.rs` | Lockless flow table |
| `src/buffer.rs` | Zero-copy buffers |
| `src/pipeline.rs` | 6-stage pipeline |
| `src/crypto.rs` | WireGuard/IPsec |
| `src/stats.rs` | Atomic metrics |
| `benches/flow_table.rs` | Flow benchmarks |
| `benches/packet_pipeline.rs` | Pipeline benchmarks |
