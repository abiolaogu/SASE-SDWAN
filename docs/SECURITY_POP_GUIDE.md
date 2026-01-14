# Security PoP Gateway Guide

Comprehensive guide for the Security PoP gateway in OpenSASE-Lab.

## Overview

The Security PoP is an Alpine-based gateway providing:

| Component | Purpose |
|-----------|---------|
| **Suricata** | IPS/IDS in inline mode |
| **Unbound** | Secure DNS resolver with logging |
| **Squid** | SWG-lite proxy (no TLS interception) |
| **nftables** | Zone-based firewall |
| **Node Exporter** | Prometheus metrics |
| **Management API** | REST API for control |

> **Note:** This is an OPNsense substitute. OPNsense doesn't run well in containers due to its FreeBSD kernel requirements. This Alpine-based solution provides equivalent functionality for lab purposes.

## Architecture

```
                    Internet
                        │
                        ▼
    ┌───────────────────────────────────────┐
    │          Security PoP (10.200.0.1)     │
    │  ┌─────────────────────────────────┐  │
    │  │         nftables Firewall       │  │
    │  └─────────────┬───────────────────┘  │
    │                │                       │
    │  ┌─────────────▼───────────────────┐  │
    │  │         Suricata IPS            │  │
    │  │    (inline inspection)          │  │
    │  └─────────────┬───────────────────┘  │
    │                │                       │
    │  ┌─────────────▼───────────────────┐  │
    │  │    Squid Proxy (SWG-lite)       │  │
    │  │    Port 3128 (optional)         │  │
    │  └─────────────┬───────────────────┘  │
    │                │                       │
    │  ┌─────────────▼───────────────────┐  │
    │  │     Unbound DNS Resolver        │  │
    │  │         Port 53                 │  │
    │  └─────────────────────────────────┘  │
    │                                        │
    │  ┌─────────────────────────────────┐  │
    │  │   Logs → Wazuh (Eve JSON)       │  │
    │  │   Metrics → Prometheus          │  │
    │  └─────────────────────────────────┘  │
    └───────────────────────────────────────┘
```

---

## Quick Start

### Start Security PoP

```bash
# Start only the Security PoP
make up-security

# Or as part of full stack
make up
```

### Verify Services

```bash
# Check health
curl http://localhost:8081/api/health

# View Suricata alerts
curl http://localhost:8081/api/suricata/alerts

# Get DNS stats
curl http://localhost:8081/api/dns/stats
```

### Trigger Test Alert

```bash
# HTTP test
curl -H 'User-Agent: OpenSASE-Test' http://localhost:8081/opensase-test

# Check alert
docker exec security-pop tail /var/log/suricata/fast.log
```

---

## Safe Demo Alerts

These rules trigger on non-malicious traffic for demonstration:

| SID | Trigger | Command |
|-----|---------|---------|
| 9000001 | URI `/opensase-test` | `curl http://security-pop/opensase-test` |
| 9000002 | User-Agent `OpenSASE-Test` | `curl -H 'User-Agent: OpenSASE-Test' http://...` |
| 9000003 | Header `X-OpenSASE-Test` | `curl -H 'X-OpenSASE-Test: true' http://...` |
| 9000010 | DNS `test.opensase.lab` | `dig @10.200.0.1 test.opensase.lab` |
| 9000011 | DNS `blocked.demo.lab` | `dig @10.200.0.1 blocked.demo.lab` |

### Example: Generate Multiple Alerts

```bash
# Run test generator
for i in {1..5}; do
  curl -s -H 'User-Agent: OpenSASE-Test' http://localhost:8081/test
  sleep 1
done

# View alerts
docker exec security-pop tail -20 /var/log/suricata/fast.log
```

---

## Suricata IPS Configuration

### Performance Settings

Location: `docker/security-pop/suricata/suricata.yaml`

| Setting | Value | Purpose |
|---------|-------|---------|
| `runmode` | workers | Multi-threaded processing |
| `af-packet.threads` | auto | Auto-detect CPU cores |
| `af-packet.cluster-type` | cluster_flow | Flow-based distribution |
| `af-packet.use-mmap` | yes | Memory-mapped packet capture |
| `af-packet.tpacket-v3` | yes | Latest tpacket version |
| `af-packet.ring-size` | 2048 | Buffer ring size |
| `af-packet.buffer-size` | 64mb | Total buffer memory |

### CPU Pinning (for bare metal)

```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [0]
    - receive-cpu-set:
        cpu: [0]
    - worker-cpu-set:
        cpu: [1,2,3]
        mode: "exclusive"
```

### Memory Tuning

```yaml
# Flow tracking
flow:
  memcap: 64mb          # Increase for high connection counts
  hash-size: 65536

# TCP reassembly
stream:
  memcap: 128mb         # Increase for high-throughput
  reassembly:
    memcap: 256mb       # Increase for large file transfers
```

### IPS Mode Configuration

```yaml
af-packet:
  - interface: eth0
    copy-mode: ips       # Inline IPS mode
    copy-iface: eth0     # Same interface (software bridge)
```

---

## Performance Tuning Guide

### System Prerequisites

```bash
# Increase ring buffer (host system)
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
sysctl -w net.core.netdev_max_backlog=5000

# Disable CPU frequency scaling
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  echo performance > $cpu
done
```

### Netmap/XDP Considerations

| Mode | Pros | Cons | Use Case |
|------|------|------|----------|
| **AF_PACKET** | Easy setup, good performance | Higher CPU overhead | Docker, VMs |
| **Netmap** | Very high performance | Requires driver support | Bare metal |
| **XDP/eBPF** | Kernel-level speed | Complex setup | Production |

For Docker labs, AF_PACKET is recommended.

### Logging Levels

| Level | Use Case | Impact |
|-------|----------|--------|
| `notice` | Production | Minimal logging overhead |
| `info` | Debugging | Moderate overhead |
| `debug` | Development | High overhead, large logs |

Configure in `suricata.yaml`:

```yaml
logging:
  default-log-level: notice
```

### Rule Optimization

```bash
# Update rules with suricata-update
docker exec security-pop suricata-update

# Count active rules
docker exec security-pop suricatasc -c 'running-mode'
```

---

## Log Export

### To Wazuh (EVE JSON)

Suricata writes EVE JSON to `/var/log/suricata/eve.json`, which is mounted into the Wazuh manager container.

Wazuh configuration in `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
  <label key="log_type">suricata</label>
</localfile>
```

### To Prometheus

The Security PoP exposes metrics at `:9100` (node_exporter) and `:8080/metrics` (custom metrics).

Prometheus scrape config:

```yaml
- job_name: 'security-pop'
  static_configs:
    - targets: ['security-pop:9100']

- job_name: 'security-pop-api'
  static_configs:
    - targets: ['security-pop:8080']
  metrics_path: /metrics
```

---

## Squid Proxy (SWG-lite)

### Usage

Configure clients to use proxy at `10.200.0.1:3128`.

```bash
# Test proxy
curl -x http://10.200.0.1:3128 http://example.com
```

### Features

- **URL filtering** (blocklist in config)
- **Access logging** (Wazuh-compatible format)
- **Caching** (100MB default)
- **No TLS interception** (privacy-preserving)

### Blocked Domains (Demo)

| Domain | Purpose |
|--------|---------|
| `*.blocked.demo.lab` | Demo blocking |
| `*.malware-test.lab` | Demo blocking |
| `*.phishing-demo.lab` | Demo blocking |

---

## API Reference

Base URL: `http://localhost:8081`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Service health status |
| `/api/suricata/stats` | GET | Suricata counters |
| `/api/suricata/alerts` | GET | Recent alerts |
| `/api/suricata/rules/reload` | POST | Reload rules |
| `/api/dns/stats` | GET | Unbound statistics |
| `/api/dns/flush` | POST | Flush DNS cache |
| `/api/proxy/stats` | GET | Squid statistics |
| `/api/firewall/rules` | GET | nftables ruleset |
| `/api/firewall/block` | POST | Block IP |
| `/api/firewall/unblock` | POST | Unblock IP |
| `/api/demo/trigger-alert` | POST | Trigger test alert |
| `/metrics` | GET | Prometheus metrics |

---

## Troubleshooting

### Suricata Not Starting

```bash
# Check logs
docker exec security-pop cat /var/log/suricata/suricata.log

# Verify rules
docker exec security-pop suricata -T -c /etc/suricata/suricata.yaml
```

### High CPU Usage

1. Reduce logging level to `notice`
2. Disable unnecessary protocol parsers in `app-layer.protocols`
3. Increase `max-pending-packets`
4. Use BPF filters to exclude high-volume traffic

### No Alerts Generating

1. Verify rules loaded: `suricatasc -c 'ruleset-stats'`
2. Check interface is correct in config
3. Ensure traffic is flowing through container

---

## OPNsense Comparison

| Feature | OPNsense | Security PoP |
|---------|----------|--------------|
| IDS/IPS | Suricata | Suricata |
| DNS | Unbound | Unbound |
| Proxy | Squid | Squid |
| Firewall | pf | nftables |
| Web UI | Yes | API only |
| Container-friendly | No | Yes |

---

## Related Documentation

- [Architecture Overview](ARCHITECTURE.md)
- [SD-WAN Guide](SDWAN_GUIDE.md)
- [Operations Runbook](OPS_RUNBOOK.md)
- [Suricata Docs](https://suricata.readthedocs.io/)
