# OpenSASE VPP Engine (OVE)

## 100+ Gbps Data Plane for Enterprise SASE

The OpenSASE VPP Engine is a high-performance packet processing engine built on FD.io VPP (Vector Packet Processing) with DPDK for kernel-bypass, zero-copy packet handling.

### Performance Targets

| Metric | Target |
|--------|--------|
| Throughput | 100+ Gbps |
| Latency | < 10μs |
| PPS (64B) | 100M+ |
| Vector Size | 256 packets |

### Architecture

```
dpdk-input → ethernet-input → ip4-input → opensase-security
                                              ↓
                                         opensase-policy
                                              ↓
                                         opensase-dlp
                                              ↓
                                         opensase-classify
                                              ↓
                                         opensase-qos
                                              ↓
                                         wireguard-encrypt
                                              ↓
                                         dpdk-output
```

### Directory Structure

```
vpp/
├── plugins/
│   ├── opensase/          # SASE processing nodes
│   └── wireguard_tunnel/  # WireGuard encryption
├── config/                # VPP configuration files
├── scripts/               # Setup and management scripts
└── tests/                 # Test suites
```

### Building

```bash
# Prerequisites (Ubuntu 22.04)
sudo apt-get install vpp vpp-dev vpp-plugin-core vpp-plugin-dpdk
sudo apt-get install libhyperscan-dev libndpi-dev

# Build plugins
cd vpp
make build

# Install plugins
sudo make install
```

### Running

```bash
# Setup hugepages (32GB)
sudo ./scripts/setup_hugepages.sh

# Bind NICs to DPDK
sudo ./scripts/bind_dpdk.sh 0000:81:00.0 0000:81:00.1

# Start VPP
sudo vpp -c config/startup.conf
```

### Graph Nodes

| Node | Purpose |
|------|---------|
| `opensase-security` | Entry point, session tracking |
| `opensase-policy` | Policy enforcement |
| `opensase-dlp` | Data loss prevention |
| `opensase-classify` | Application classification |
| `opensase-qos` | QoS marking and shaping |

### Hardware Requirements

- **NICs**: Mellanox ConnectX-6 or Intel E810 (100GbE)
- **CPU**: 32+ cores (AMD EPYC or Intel Xeon)
- **RAM**: 256GB+ with hugepages enabled
- **Storage**: NVMe for logging

### License

Apache 2.0
