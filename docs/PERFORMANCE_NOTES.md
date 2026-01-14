# OpenSASE-Lab Performance Notes

This document provides performance tuning guidance for production deployments.

---

## Resource Baseline

### Minimum Requirements

| Profile | RAM | CPU | Disk I/O | Network |
|---------|-----|-----|----------|---------|
| Lite | 8GB | 4 cores | HDD OK | 100 Mbps |
| Full | 16GB | 8 cores | SSD recommended | 1 Gbps |
| Production | 32GB+ | 16 cores | NVMe | 10 Gbps |

### Per-Component Breakdown

| Component | RAM | CPU | Notes |
|-----------|-----|-----|-------|
| FlexiWAN Controller | 1GB | 1 core | Scales with device count |
| FlexiWAN Edge (x3) | 512MB each | 0.5 core | WireGuard is CPU-efficient |
| Security PoP (Suricata) | 4GB | 4 cores | Most resource-intensive |
| OpenZiti Controller | 512MB | 0.5 core | Light footprint |
| OpenZiti Routers (x3) | 256MB each | 0.25 core | Efficient Go runtime |
| Wazuh Manager | 2GB | 2 cores | Scales with log volume |
| Wazuh Indexer | 4GB | 2 cores | JVM heap sizing critical |
| Wazuh Dashboard | 1GB | 1 core | Node.js based |
| Keycloak | 1GB | 1 core | JVM application |
| Prometheus | 512MB | 0.5 core | Scales with metric count |
| Grafana | 512MB | 0.5 core | Light unless many users |
| Portal | 256MB | 0.25 core | FastAPI is efficient |

---

## What to Tune First

### Priority 1: Suricata IPS

Suricata is the bottleneck for throughput. Tune in this order:

**1. CPU Affinity & Threading**
```yaml
# suricata.yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 1 ]
    - worker-cpu-set:
        cpu: [ 2, 3 ]
```

**2. Memory for Flow Table**
```yaml
flow:
  memcap: 256mb        # Increase for high connection counts
  hash-size: 65536     # Power of 2, tune for flow count
  prealloc: 10000      # Pre-allocate flow entries
```

**3. Rule Optimization**
```bash
# Disable unnecessary rule categories
suricata-update disable-ruleset emerging-games
suricata-update disable-ruleset emerging-chat

# Use rule profiling
suricata --engine-analysis
```

**4. Capture Method**
```yaml
# Use AF_PACKET with kernel bypass for high throughput
af-packet:
  - interface: eth0
    cluster-type: cluster_flow
    ring-size: 200000
    block-size: 32768
```

**Expected Throughput:**
| Configuration | Throughput |
|---------------|------------|
| Default | ~1 Gbps |
| Tuned (4 cores) | ~5 Gbps |
| Kernel bypass (XDP) | ~10+ Gbps |

---

### Priority 2: Wazuh Indexer (OpenSearch)

JVM heap sizing is critical:

**1. Set Heap Size (50% of available RAM, max 32GB)**
```bash
# In docker-compose.yml
environment:
  - "OPENSEARCH_JAVA_OPTS=-Xms4g -Xmx4g"
```

**2. Index Lifecycle Management**
```json
// Automatically delete old indices
{
  "policy": {
    "phases": {
      "hot": { "actions": {} },
      "delete": { "min_age": "30d", "actions": { "delete": {} } }
    }
  }
}
```

**3. Shard Sizing**
- Target: 20-40GB per shard
- For lab: 1 shard is sufficient
- Production: Calculate based on daily log volume

---

### Priority 3: WireGuard (FlexiWAN)

WireGuard is already highly optimized. Key tuning:

**1. MTU Optimization**
```yaml
# Reduce MTU to avoid fragmentation
# WireGuard overhead: 60 bytes (IPv4) or 80 bytes (IPv6)
mtu: 1420  # For typical 1500 MTU networks
```

**2. Kernel Parameters**
```bash
# Increase socket buffers
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
```

---

### Priority 4: OpenZiti

Ziti is lightweight but scales with identity count:

**1. Session Cache**
```yaml
# In controller config
edge:
  api:
    sessionTimeout: 30m
    apiSessionTimeout: 60m
```

**2. Connection Limits**
```yaml
# In router config
listeners:
  - binding: edge
    options:
      maxConnections: 10000
```

---

## Logging Overhead

### Reducing Log Volume

| Source | Default | Tuned |
|--------|---------|-------|
| Suricata | All flows | Alerts only |
| FlexiWAN | Debug | Info |
| Wazuh | All events | Security only |

**Suricata: Log alerts only**
```yaml
outputs:
  - eve-log:
      types:
        - alert
        # - flow  # Disable flow logging
        # - dns   # Disable DNS logging unless needed
```

**FlexiWAN: Reduce log level**
```bash
# In .env
FLEXIWAN_LOG_LEVEL=info  # Default is debug
```

---

## Network Optimization

### Docker Network Driver

For best performance:
```yaml
networks:
  pop-net:
    driver: bridge
    driver_opts:
      com.docker.network.driver.mtu: 1500
```

### Host Networking (Advanced)

For maximum throughput, use host networking for the Security PoP:
```yaml
services:
  security-pop:
    network_mode: host
    # Note: Requires manual IP configuration
```

---

## Monitoring Performance

### Key Metrics to Watch

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Suricata CPU | >70% | >90% | Add cores or tune rules |
| Suricata Drops | >0.1% | >1% | Increase ring buffer |
| Wazuh Indexer Heap | >75% | >90% | Increase heap or add nodes |
| WireGuard Handshakes | >100/s | >500/s | Check for DDoS |
| Ziti Sessions | >10K | >50K | Scale routers |

### Grafana Dashboards

Pre-built performance dashboards included:
- `SD-WAN Performance` - Tunnel throughput, latency
- `Security PoP` - Suricata stats, drops, alerts/sec
- `ZTNA Sessions` - Active sessions, policy latency
- `System Resources` - CPU, RAM, disk, network

---

## Scaling Guidelines

### Horizontal Scaling

| Component | Scale How | When |
|-----------|-----------|------|
| FlexiWAN Edge | Add more edges | New sites |
| Ziti Routers | Add edge routers | More users per site |
| Wazuh Indexer | Add nodes to cluster | Log volume >100GB/day |
| Security PoP | Multiple PoPs | Geographic distribution |

### Vertical Scaling

| Component | Scale What | When |
|-----------|------------|------|
| Suricata | More CPU cores | Throughput bottleneck |
| Wazuh Indexer | More RAM | Query performance |
| FlexiWAN Controller | More RAM | >500 devices |

---

## Production Checklist

- [ ] Suricata tuned for expected throughput
- [ ] Wazuh Indexer heap set to 50% of RAM
- [ ] Log retention policies configured
- [ ] Monitoring dashboards reviewed
- [ ] Alerting thresholds set
- [ ] Disk space alerts configured
- [ ] Network MTU verified end-to-end
- [ ] Kernel parameters optimized (sysctl)

---

## Benchmarks

### Test Commands

```bash
# WireGuard throughput
iperf3 -c 10.200.0.1 -t 30 -P 4

# Suricata latency impact
ping -c 100 10.200.0.1 | tail -1

# Ziti overhead
curl -o /dev/null -w "%{time_total}" http://app1.ziti

# Indexer query performance
time curl -XGET 'localhost:9200/wazuh-*/_search?size=1000'
```

### Reference Results (8-core, 32GB RAM)

| Test | Result |
|------|--------|
| WireGuard throughput | 2.4 Gbps |
| Suricata inline latency | +0.3ms |
| Ziti app access | 12ms total |
| Wazuh 1000-doc query | 45ms |

---

## Last Updated

2026-01-13 | Version 1.0
