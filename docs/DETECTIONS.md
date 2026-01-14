# OpenSASE-Lab Detection Capabilities

Comprehensive documentation of security detection capabilities and limitations.

## Overview

The OpenSASE-Lab SIEM stack provides centralized visibility across all SASE components:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Wazuh Manager                                 │
│                  (Detection Engine)                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
    ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
    │Suricata │        │FlexiWAN │        │OpenZiti │
    │  IPS    │        │  SD-WAN │        │  ZTNA   │
    └─────────┘        └─────────┘        └─────────┘
```

---

## Detection Categories

### 1. Network Intrusion Detection (Suricata)

| Rule ID | Detection | Severity | Description |
|---------|-----------|----------|-------------|
| 100001 | Suricata Alert | Medium | Generic IPS signature match |
| 100002 | High Severity Alert | High | Severity 1 IPS alerts |
| 100003 | Medium Severity Alert | Medium | Severity 2 IPS alerts |
| 100010 | OpenSASE Test Alert | Low | Safe demo signature triggers |
| 100011 | DNS Query Alert | Low | Queries for OpenSASE domains |

**Log Source:** `/var/log/suricata/eve.json`

**What's Detected:**
- Malware signatures (ET Open rules)
- Protocol anomalies
- Known attack patterns
- Network policy violations
- DNS tunneling indicators

**Limitations:**
- TLS-encrypted traffic not inspected (no TLS interception)
- Custom signatures require manual rule creation
- High-volume environments may need tuning

### 2. SD-WAN Events (FlexiWAN)

| Rule ID | Detection | Severity | Description |
|---------|-----------|----------|-------------|
| 100100 | Device Connected | Info | Edge device came online |
| 100101 | Device Disconnected | Medium | Edge device went offline |
| 100102 | Tunnel Down | High | Overlay tunnel failure |
| 100103 | Tunnel Up | Info | Overlay tunnel established |
| 100104 | WAN Failover | Medium | Path switched to backup WAN |
| 100105 | Policy Applied | Info | Configuration change deployed |

**Log Source:** `/var/log/flexiwan/*.log`

**What's Detected:**
- Device availability changes
- Tunnel state transitions
- WAN failover events
- Policy updates

**Limitations:**
- Depends on FlexiWAN log export configuration
- Real-time alerting depends on log shipping latency
- Some events only available in commercial edition

### 3. Zero Trust Access (OpenZiti)

| Rule ID | Detection | Severity | Description |
|---------|-----------|----------|-------------|
| 100200 | Session Created | Info | User connected to service |
| 100201 | Session Terminated | Low | User session ended |
| 100202 | Auth Failed | Medium | Authentication failure |
| 100203 | Access Denied | Medium | Authorization failure |
| 100204 | Router Offline | High | Fabric router unavailable |
| 100205 | Identity Enrolled | Low | New identity provisioned |

**Log Source:** `/var/log/ziti/events.json`

**What's Detected:**
- Authentication success/failure
- Authorization violations
- Session lifecycle
- Fabric topology changes

**Limitations:**
- Requires Ziti event logging enabled
- Identity to user mapping needs external context
- Service timing data not included

### 4. DNS Security (Unbound)

| Rule ID | Detection | Severity | Description |
|---------|-----------|----------|-------------|
| 100300 | Blocked Domain | Medium | Query for blocked domain |
| 100301 | High Query Rate | High | Possible DNS tunneling |

**Log Source:** `/var/log/unbound/queries.log`

**What's Detected:**
- DNS queries to blocked domains
- Unusual query patterns
- Resolution failures

**Limitations:**
- No DNSSEC validation alerts (yet)
- No DGA (Domain Generation Algorithm) detection
- Query content not inspected

### 5. Web Proxy (Squid)

| Rule ID | Detection | Severity | Description |
|---------|-----------|----------|-------------|
| 100400 | Access Denied | Low | Blocked URL access |
| 100401 | High Volume | Medium | Unusual traffic from client |

**Log Source:** `/var/log/squid/access.log`

**What's Detected:**
- Policy violations
- Access denials
- Traffic anomalies

**Limitations:**
- No TLS interception (privacy-preserving)
- HTTPS content not visible
- URL categories not supported

---

## Correlation Rules

Advanced rules that combine events from multiple sources:

| Rule ID | Correlation | Severity | Description |
|---------|-------------|----------|-------------|
| 100500 | Multiple Auth Failures | High | 5+ auth failures from same IP in 2 min |
| 100501 | IPS + Auth Failure | Critical | IPS alert followed by auth failure (same IP) |
| 100502 | Device + Tunnel Down | High | Device offline with associated tunnel failure |

---

## Alert Levels

| Level | Description | Response |
|-------|-------------|----------|
| 0-2 | Ignore | No action |
| 3-5 | Low | Log and review |
| 6-8 | Medium | Investigate promptly |
| 9-11 | High | Immediate investigation |
| 12+ | Critical | Incident response |

---

## Log Ingestion Pipeline

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Suricata   │────▶│ EVE JSON     │────▶│             │
│             │     │ /var/log/    │     │             │
└─────────────┘     └──────────────┘     │             │
                                         │             │
┌─────────────┐     ┌──────────────┐     │   Wazuh     │
│  FlexiWAN   │────▶│ Syslog/JSON  │────▶│   Manager   │
│             │     │ Port 514     │     │             │
└─────────────┘     └──────────────┘     │             │
                                         │             │
┌─────────────┐     ┌──────────────┐     │             │
│  OpenZiti   │────▶│ Events JSON  │────▶│             │
│             │     │ /var/log/    │     │             │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
                                                ▼
                                         ┌─────────────┐
                                         │   Wazuh     │
                                         │   Indexer   │
                                         │ (OpenSearch)│
                                         └──────┬──────┘
                                                │
                                                ▼
                                         ┌─────────────┐
                                         │   Wazuh     │
                                         │  Dashboard  │
                                         └─────────────┘
```

---

## Testing Detections

### Generate Synthetic Alerts

```bash
# Generate all alert types
./scripts/generate-alerts.sh

# Generate specific types
./scripts/generate-alerts.sh suricata
./scripts/generate-alerts.sh dns
./scripts/generate-alerts.sh wazuh
```

### Trigger Safe Demo Alerts

```bash
# Suricata IPS test
curl -H 'User-Agent: OpenSASE-Test' http://localhost:8081/test

# DNS security test
docker exec security-pop dig @localhost blocked.demo.lab

# View alerts
docker exec wazuh-manager tail -20 /var/ossec/logs/alerts/alerts.json | jq
```

---

## Dashboard Views

### OpenSASE-Lab Overview

Access: **http://localhost:5601** → Dashboards → OpenSASE-Lab Overview

Panels:
- Total alerts by severity
- Alert trend (24h)
- Top triggered rules
- Events by source (Suricata, FlexiWAN, Ziti)
- Active tunnels/sessions
- Recent critical alerts

### Creating Custom Dashboards

1. Login to Wazuh Dashboard
2. Navigate to: **Dashboards** → **Create**
3. Add visualizations for:
   - `rule.groups: "opensase"`
   - `rule.id: 100*` (custom rules)
   - `data.log_type: "suricata"`

---

## Custom Rule Development

### Adding New Suricata Rules

```bash
# Add to custom.rules
echo 'alert http any any -> any any (msg:"My Custom Rule"; content:"pattern"; sid:9999999; rev:1;)' \
  >> docker/security-pop/suricata/rules/custom.rules

# Reload rules
docker exec security-pop suricatasc -c 'reload-rules'
```

### Adding Wazuh Rules

```xml
<!-- Add to docker/wazuh/manager/rules/opensase_rules.xml -->
<rule id="100999" level="7">
  <match>my-pattern</match>
  <description>My custom detection</description>
  <group>custom,</group>
</rule>
```

---

## Known Limitations

### Detection Gaps

| Gap | Reason | Mitigation |
|-----|--------|------------|
| Encrypted traffic | No TLS interception | Use endpoint agents |
| Zero-day attacks | No ML/behavioral analysis | Regular rule updates |
| Insider threats | Limited user context | Integrate with IAM |
| Cloud workloads | Focus on network | Add cloud log ingestion |

### Performance Considerations

| Component | Bottleneck | Tuning |
|-----------|------------|--------|
| Suricata | High throughput | CPU pinning, ring buffer |
| Wazuh Manager | Event volume | Increase worker threads |
| Indexer | Storage | Index lifecycle management |

### Integration Gaps

| System | Status | Notes |
|--------|--------|-------|
| FlexiWAN API | Partial | Limited log export in OSS |
| OpenZiti OIDC | Not integrated | Uses separate PKI |
| EDR/Endpoint | Not included | Lab focuses on network |

---

## Roadmap

Future detection capabilities to consider:

1. **Threat Intelligence Integration** - IoC feeds for known malicious IPs/domains
2. **UEBA** - User and Entity Behavior Analytics
3. **ML-based Anomaly Detection** - Baseline traffic patterns
4. **SOAR Integration** - Automated response playbooks
5. **Cloud Log Ingestion** - AWS CloudTrail, Azure Activity Logs

---

## Related Documentation

- [Security PoP Guide](SECURITY_POP_GUIDE.md)
- [ZTNA Guide](ZTNA_GUIDE.md)
- [SD-WAN Guide](SDWAN_GUIDE.md)
- [Wazuh Documentation](https://documentation.wazuh.com/)
