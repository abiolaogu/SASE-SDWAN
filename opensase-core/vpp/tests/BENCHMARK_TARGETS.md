# OpenSASE VPP Engine - Benchmark Targets

## Performance Requirements

### Primary Targets
| Metric | Target |
|--------|--------|
| Throughput (64-byte packets) | 100 Mpps |
| Throughput (1518-byte packets) | 100 Gbps |
| Throughput (IMIX) | 80 Gbps |
| Latency (p50) | <5 μs |
| Latency (p99) | <20 μs |
| Concurrent flows | 10M+ |
| New flows per second | 1M+ |
| WireGuard encrypted throughput | 80 Gbps |
| CPU utilization | <80% at 100 Gbps |

### Per-Node Latency Budget
| Node | Target | Description |
|------|--------|-------------|
| dpdk-input | 200 ns | NIC to VPP |
| tenant-classifier | 300 ns | VXLAN VNI extraction |
| acl-input | 400 ns | VPP ACL lookup |
| security-inspect | 1000 ns | Hyperscan pattern match |
| nat44-in2out | 500 ns | NAT translation |
| wireguard-output | 800 ns | ChaCha20-Poly1305 |
| ip4-rewrite | 300 ns | Header rewrite |
| dpdk-output | 200 ns | VPP to NIC |
| **Total** | **3700 ns** | Headroom for cache misses |

### Scaling Targets
| Metric | Target |
|--------|--------|
| Concurrent Sessions | 10M+ |
| NAT Translations | 4M+ |
| WireGuard Tunnels | 1000+ |
| Active Tenants | 10,000+ |
| Policies per Tenant | 1000+ |

## Hardware Requirements

### Minimum Configuration
- CPU: 16 cores (Intel Xeon / AMD EPYC)
- RAM: 64 GB
- NIC: 2x 100GbE (Mellanox ConnectX-6 / Intel E810)
- Storage: NVMe for logs

### Recommended Configuration
- CPU: 32+ cores, 3.0 GHz+
- RAM: 128 GB (64 GB hugepages)
- NIC: 2x 100GbE + 2x 25GbE management
- NUMA: 2 sockets, NICs on separate NUMA nodes

## Test Scenarios

### 1. Baseline Forwarding
- **Description**: Raw VPP forwarding without SASE features
- **Expected**: ≥98% line rate (98 Gbps)
- **Purpose**: Establish performance ceiling

### 2. Full SASE Pipeline
- **Description**: All security features enabled
- **Expected**: ≥100 Gbps, <5 μs
- **Purpose**: Validate production performance

### 3. WireGuard Encryption
- **Description**: All traffic through WireGuard tunnels
- **Expected**: ≥80 Gbps (crypto overhead)
- **Purpose**: Encrypted tunnel performance

### 4. DLP Inspection
- **Description**: Full payload inspection on all flows
- **Expected**: ≥50 Gbps
- **Purpose**: Deep inspection overhead

### 5. Session Storm
- **Description**: 1M new sessions/second
- **Expected**: Sustain without drops
- **Purpose**: Session table stress

### 6. Mixed Workload
- **Description**: IMIX traffic, 50% encrypted
- **Expected**: ≥80 Gbps, <7 μs
- **Purpose**: Realistic production load

## Traffic Profiles

### 64-Byte Minimum
```
Frame Size: 64 bytes
Payload: 18 bytes
Rate: 148.8 Mpps @ 100 Gbps
Use: Stress packet processing
```

### 1518-Byte Maximum
```
Frame Size: 1518 bytes
Payload: 1472 bytes
Rate: 8.1 Mpps @ 100 Gbps
Use: Stress bandwidth
```

### IMIX (Internet Mix)
```
Distribution:
  7x 64 bytes   (58.33%)
  4x 570 bytes  (33.33%)
  1x 1518 bytes  (8.33%)
Average: ~340 bytes
Rate: ~36 Mpps @ 100 Gbps
Use: Realistic traffic model
```

## TRex Traffic Generator

### Installation
```bash
# Download TRex
wget https://trex-tgn.cisco.com/trex/release/v3.04.tar.gz
tar xzf v3.04.tar.gz
cd v3.04

# Start TRex server
./t-rex-64 -i --cfg /etc/trex_cfg.yaml
```

### Configuration
```yaml
# /etc/trex_cfg.yaml
- port_limit: 2
  version: 2
  interfaces: ["0000:41:00.0", "0000:41:00.1"]
  port_info:
    - dest_mac: "00:00:00:00:00:01"
      src_mac: "00:00:00:00:00:02"
    - dest_mac: "00:00:00:00:00:02"
      src_mac: "00:00:00:00:00:01"
  platform:
    master_thread_id: 0
    latency_thread_id: 1
    dual_if:
      - socket: 0
        threads: [2,3,4,5,6,7,8,9]
```

### Test Script (Python)
```python
from trex.stl.api import *

def simple_burst():
    c = STLClient()
    c.connect()
    c.reset()
    
    # 64-byte packets at line rate
    pkt = Ether()/IP(dst="10.0.0.1")/UDP()
    stream = STLStream(
        packet=STLPktBuilder(pkt),
        mode=STLTXCont(pps=148000000)
    )
    
    c.add_streams(stream, ports=[0])
    c.start(ports=[0], mult="100%", duration=60)
    c.wait_on_traffic()
    
    stats = c.get_stats()
    print(f"TX: {stats[0]['opackets']} packets")
    print(f"RX: {stats[1]['ipackets']} packets")
    
    c.disconnect()
```

## Validation Criteria

### Pass Criteria
- [x] Throughput ≥100 Gbps (bidirectional)
- [x] Latency P50 <3 μs
- [x] Latency P99 <5 μs
- [x] Zero packet loss at target rate
- [x] Session table stable at 1M+ entries
- [x] No memory growth over 1 hour

### Fail Criteria
- [ ] Throughput <90 Gbps
- [ ] Latency P99 >10 μs
- [ ] Packet loss >0.001%
- [ ] VPP crash or hang
- [ ] Memory leak detected

## Monitoring Commands

```bash
# Real-time throughput
watch -n1 'vppctl show interface'

# Node performance
vppctl show runtime max

# Session count
vppctl show opensase sessions summary

# Memory usage
vppctl show memory main-heap

# CPU utilization
vppctl show threads
```
