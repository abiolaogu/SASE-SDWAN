# OpenSASE Security Operations Platform (OSOP)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SECURITY OPERATIONS PLATFORM                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │    SIEM      │  │    SOAR      │  │    Case      │  │   Threat    │ │
│  │ Integration  │  │  Playbooks   │  │ Management   │  │   Hunting   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │  Forensics   │  │  Compliance  │  │   Alert      │  │   Metrics   │ │
│  │  Collection  │  │  Reporting   │  │   Router     │  │   Export    │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## SIEM Integration

| Platform | Protocol | Capabilities |
|----------|----------|--------------|
| **Splunk** | HEC REST API | Events, Alerts, Search (SPL) |
| **Elastic** | Bulk REST API | Events, Alerts, Search (EQL/KQL) |
| **Microsoft Sentinel** | Log Analytics API | Events, Alerts, Search (KQL) |
| **IBM QRadar** | REST API | Events, Alerts, Offenses (AQL) |

### Event Flow
```
OpenSASE Components → SecurityEvent → SIEM Integration → All Connected SIEMs
```

---

## SOAR Playbooks

### Playbook Structure
```yaml
playbook:
  id: malware-response
  name: Malware Response
  trigger: AlertType(MalwareDetected)
  steps:
    - id: enrich
      action: EnrichIndicator
      on_success: isolate
    - id: isolate
      action: IsolateHost
      condition: severity > Medium
      on_success: case
    - id: case
      action: CreateCase
    - id: notify
      action: SendSlack
```

### Available Actions

| Category | Actions |
|----------|---------|
| **Enrichment** | EnrichIndicator, LookupAsset, LookupUser, QuerySiem |
| **Response** | BlockIp, IsolateHost, DisableUser, QuarantineFile |
| **Notification** | SendEmail, SendSlack, CreateTicket, PageOnCall |
| **Case** | CreateCase, UpdateCase, EscalateCase |
| **Control** | Wait, Parallel, Conditional |

---

## Case Management

### Case Lifecycle
```
New → Open → InProgress → Resolved → Closed
                ↓
            OnHold
```

### Case Properties

| Field | Description |
|-------|-------------|
| Priority | P1 (1hr), P2 (4hr), P3 (24hr), P4 (72hr) |
| Type | Incident, DataBreach, Malware, Phishing... |
| Observable | IPs, Domains, Hashes, Emails |
| Tasks | Investigation checklist |
| Timeline | Audit trail of all activities |

---

## Threat Hunting

### Built-in Queries

| Query | MITRE | Description |
|-------|-------|-------------|
| Beaconing | T1071 | C2 callback detection |
| DNS Tunneling | T1048 | Data exfiltration via DNS |
| Lateral Movement | T1021 | Unusual auth patterns |

### Threat Intel Feeds

| Feed | Type |
|------|------|
| AlienVault OTX | Community |
| AbuseIPDB | Community |
| Internal IOCs | Internal |

---

## Compliance Frameworks

| Framework | Controls |
|-----------|----------|
| **SOC 2 Type II** | CC6.1 Logical Access, CC6.6 Boundaries |
| **ISO 27001:2022** | A.5.1 Policies, A.8.1 Access Control |
| **NIST CSF** | ID.AM Asset Management, PR.AC Access Control |

### Assessment Output
```json
{
  "framework": "SOC 2",
  "score": 94.5,
  "status": "Compliant",
  "controls": {
    "CC6.1": "Compliant",
    "CC6.6": "PartiallyCompliant"
  }
}
```

---

## Forensics

### Evidence Types
- Memory Dump
- Disk Image
- Log Files
- Network Capture
- Process List
- Registry
- Malware Sample

### Chain of Custody
Every evidence item includes:
- SHA-256 hash
- Collector identity
- Timestamps
- Transfer history

---

## Alert Routing

| Severity | Destinations |
|----------|--------------|
| Critical | PagerDuty + Auto-Case |
| High | Slack #security + Email |
| Medium | Slack |
| Low | Log only |

---

## Integration Points

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   OpenSASE      │────▶│      OSOP       │────▶│      SIEM       │
│   Components    │     │   (sase-soc)    │     │ Splunk/Elastic  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
       │                        │                        │
       │                        ▼                        │
       │               ┌─────────────────┐              │
       │               │  SOAR/Ticketing │              │
       │               │ ServiceNow/Jira │              │
       │               └─────────────────┘              │
       │                        │                        │
       ▼                        ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Unified SOC Dashboard                       │
└─────────────────────────────────────────────────────────────────┘
```
