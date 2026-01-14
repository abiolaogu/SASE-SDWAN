# Threat Hunting Playbooks

## Overview

Pre-built hunting queries for proactive threat detection.

---

## Built-in Queries

### 1. C2 Beaconing Detection
**MITRE: T1071 - Application Layer Protocol**

Detects regular-interval communications indicative of command & control.

| Parameter | Value |
|-----------|-------|
| Detection | Low stddev in connection intervals |
| Threshold | Variance < 0.1 |
| Time Window | 24 hours |
| Schedule | Every hour |

**Indicators:**
- Regular HTTP/HTTPS callbacks
- Fixed time intervals (±5%)
- Encrypted payloads
- Unusual User-Agent

---

### 2. DNS Tunneling Detection
**MITRE: T1071.004 - DNS**

Detects data exfiltration via DNS queries.

| Parameter | Value |
|-----------|-------|
| Detection | High entropy DNS queries |
| Threshold | Entropy > 3.5 |
| Query Length | > 50 characters |
| Schedule | Every hour |

**Indicators:**
- Long subdomain names
- Base64/hex-encoded queries
- High query volume to single domain
- TXT record queries

---

### 3. Lateral Movement Detection
**MITRE: T1021 - Remote Services**

Detects movement between internal hosts.

| Parameter | Value |
|-----------|-------|
| Detection | SMB/RDP to multiple hosts |
| Threshold | > 5 unique destinations |
| Time Window | 1 hour |
| Schedule | Every 15 min |

**Indicators:**
- Single source → many destinations
- SMB/RDP/WinRM traffic
- After-hours activity
- Admin share access

---

### 4. Data Exfiltration Detection
**MITRE: T1041 - Exfiltration Over C2 Channel**

Detects large outbound data transfers.

| Parameter | Value |
|-----------|-------|
| Detection | Large outbound transfers |
| Threshold | > 100 MB in 1 hour |
| Schedule | Every 30 min |

**Indicators:**
- Unusual data volume
- After-hours transfers
- Cloud storage uploads
- Encrypted channels

---

### 5. Credential Access Detection
**MITRE: T1110 - Brute Force**

Detects password guessing attacks.

| Parameter | Value |
|-----------|-------|
| Detection | Failed auth attempts |
| Threshold | > 10 failures in 5 min |
| Schedule | Every 5 min |

**Indicators:**
- Multiple usernames from single source
- Password spray patterns
- Credential stuffing
- Lockout events

---

## Custom Query DSL

```rust
QueryDsl::And(vec![
    QueryDsl::Behavioral {
        field: "protocol".to_string(),
        operator: Operator::In,
        value: Value::Array(vec!["smb", "rdp"]),
        group_by: vec!["src_ip"],
        time_range: TimeRange::LastHours(1),
    },
    QueryDsl::Behavioral {
        field: "unique_dst_count".to_string(),
        operator: Operator::GreaterThan,
        value: Value::Int(5),
        group_by: vec!["src_ip"],
        time_range: TimeRange::LastHours(1),
    },
])
```

---

## Response Actions

| Action | Use Case |
|--------|----------|
| `Alert` | Notify SOC team |
| `Block` | Add to blocklist |
| `Quarantine` | Isolate asset |
| `NotifyTeam` | Slack/Teams alert |
| `CreateTicket` | Jira/ServiceNow |
| `EnrichIndicator` | Add context |
| `TriggerPlaybook` | Chain responses |

---

## Scheduling Options

| Type | Example |
|------|---------|
| Interval | Every 15 minutes |
| Cron | `0 * * * *` (hourly) |
| On-demand | Manual execution |
| Event-triggered | On new IOC |

---

## Performance Targets

| Query Type | Target Latency |
|------------|----------------|
| IOC Match | < 100ms |
| Behavioral | < 5s |
| MITRE Hunt | < 10s |
| Composite | < 30s |
