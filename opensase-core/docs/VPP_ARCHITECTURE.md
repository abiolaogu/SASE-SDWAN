# OpenSASE VPP Architecture Guide

## Overview

The OpenSASE VPP Engine (OVE) is a high-performance data plane built on FD.io VPP (Vector Packet Processing) with DPDK for kernel-bypass packet processing. It achieves **100+ Gbps** throughput with **<5μs** latency on COTS dedicated servers.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        OPENSASE VPP ENGINE (OVE)                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          VPP GRAPH PIPELINE                              │ │
│  │                                                                          │ │
│  │  dpdk-input                                                              │ │
│  │      │                                                                   │ │
│  │      ▼                                                                   │ │
│  │  tenant-classifier ←── VXLAN VNI extraction                              │ │
│  │      │                                                                   │ │
│  │      ▼                                                                   │ │
│  │  acl-input ←── VPP ACL plugin (firewall)                                 │ │
│  │      │                                                                   │ │
│  │      ▼                                                                   │ │
│  │  security-inspect ←── Hyperscan IPS                                      │ │
│  │      │                                                                   │ │
│  │      ▼                                                                   │ │
│  │  nat44-in2out ←── VPP NAT plugin                                         │ │
│  │      │                                                                   │ │
│  │      ▼                                                                   │ │
│  │  wireguard-output-tun ←── Encrypt                                        │ │
│  │      │                                                                   │ │
│  │      ▼                                                                   │ │
│  │  ip4-rewrite                                                             │ │
│  │      │                                                                   │ │
│  │      ▼                                                                   │ │
│  │  dpdk-output                                                             │ │
│  │                                                                          │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   DPDK      │ │  Hugepages  │ │  CPU        │ │  NUMA       │            │
│  │   Drivers   │ │  (1GB x 64) │ │  Pinning    │ │  Awareness  │            │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘            │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Custom Graph Nodes

### Node Chain (Single-Pass Processing)

| Node | Function | Target Latency |
|------|----------|----------------|
| `tenant-classifier` | Extract tenant from VXLAN VNI | 300 ns |
| `opensase-tenant` | IP-based tenant lookup (fallback) | 300 ns |
| `opensase-security` | Session tracking | 400 ns |
| `security-inspect` | Hyperscan IPS signatures | 1000 ns |
| `opensase-policy` | Policy enforcement | 400 ns |
| `opensase-dlp` | DLP inspection (optional) | 500 ns |
| `opensase-classify` | App classification | 300 ns |
| `opensase-qos` | DSCP marking | 200 ns |
| `opensase-nat` | NAT/PAT translation | 500 ns |
| `opensase-encap` | WireGuard/VXLAN encap | 500 ns |

### Node Implementation Files

```
vpp/plugins/opensase/
├── opensase.c              # Plugin registration
├── opensase.h              # Shared definitions
├── node_vxlan_classifier.c # VXLAN VNI extraction
├── node_tenant.c           # IP-based tenant lookup
├── node_security.c         # Session tracking
├── node_security_inspect.c # Hyperscan IPS
├── node_policy.c           # Policy enforcement
├── node_dlp.c              # DLP inspection
├── node_classify.c         # App classification
├── node_qos.c              # QoS marking
├── node_nat.c              # NAT/PAT
└── node_encap.c            # Tunnel encapsulation
```

## Vector Processing

VPP processes packets in **vectors** (batches) for cache efficiency:

```c
/* Process 4 packets at a time */
while (n_left_from >= 4) {
    /* Prefetch next batch */
    vlib_prefetch_buffer_header(b[4], LOAD);
    vlib_prefetch_buffer_header(b[5], LOAD);
    
    /* Process current batch */
    ip0 = vlib_buffer_get_current(b[0]);
    ip1 = vlib_buffer_get_current(b[1]);
    ip2 = vlib_buffer_get_current(b[2]);
    ip3 = vlib_buffer_get_current(b[3]);
    
    /* Execute node logic */
    ...
    
    b += 4;
    next += 4;
    n_left_from -= 4;
}
```

## Memory Architecture

### Hugepages

- **1GB pages**: Primary (best TLB efficiency)
- **2MB pages**: Fallback
- **Allocation**: 64GB total (32GB per NUMA node)

### Buffer Pools

```
buffers-per-numa: 524288
buffer-size: 2048 bytes
preallocated: 262144 per NUMA
```

### Session Tables

- Per-worker session tables (no locks)
- 1M sessions per worker
- RCU synchronization for policy updates

## CPU Architecture

### Thread Model

```
Core 0:     VPP main thread (control plane)
Cores 1-3:  Reserved for OS
Cores 4-31: VPP worker threads (28 workers)
```

### NUMA Binding

```
NUMA 0: NIC 0 (wan0) → Workers 4-17
NUMA 1: NIC 1 (lan0) → Workers 18-31
```

## Plugin Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| VPP | 24.06+ | Vector packet processing |
| DPDK | 23.11+ | Kernel bypass drivers |
| Hyperscan | 5.4+ | Regex pattern matching |
| nDPI | 4.8+ | Deep packet inspection |
| libsodium | 1.0.18+ | WireGuard crypto |

## Configuration Files

| File | Purpose |
|------|---------|
| `startup.conf` | VPP startup configuration |
| `setup.conf` | Post-startup interface config |
| `wireguard.conf` | WireGuard tunnel setup |
| `opensase.conf` | OpenSASE feature config |

## Monitoring

### VPP CLI Commands

```bash
# Show interface stats
vppctl show interface

# Show node performance
vppctl show runtime

# Show OpenSASE stats
vppctl show opensase stats

# Show IPS statistics
vppctl show opensase ips stats

# Show sessions
vppctl show opensase sessions

# Show memory usage
vppctl show memory
```

### Prometheus Metrics

VPP exports metrics via the stats segment:
- Interface counters
- Node counters
- Error counters
- Memory usage

## Security Considerations

1. **Tenant Isolation**: Per-tenant VRF and policy
2. **Encryption**: WireGuard for all inter-PoP traffic
3. **IPS**: Hyperscan-based signature matching
4. **DLP**: Pattern-based data loss prevention
5. **Rate Limiting**: Per-tenant bandwidth limits
