# OpenSASE SOC Integration Guide

## Overview

The OpenSASE Security Operations Platform (OSOP) provides:

- **SIEM Integration**: Forward events to Splunk, Elastic, Sentinel, QRadar
- **SOAR Playbooks**: Automated incident response
- **Case Management**: Incident tracking with SLA
- **Forensics**: EDR integration for evidence collection
- **Compliance**: SOC2, ISO27001, NIST reporting

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    OpenSASE Security Data                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ Network │  │ Security│  │  User   │  │  Email  │            │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘            │
│       └────────────┴────────────┴────────────┘                  │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    EVENT PROCESSING PIPELINE                     │
│  Normalize (CEF) → Enrich (Intel) → Correlate → Deduplicate    │
└───────────────────────────┬──────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │   SIEM   │  │   SOAR   │  │   Case   │
        └──────────┘  └──────────┘  └──────────┘
```

---

## SIEM Configuration

### Splunk (HEC)

```yaml
siem:
  splunk:
    enabled: true
    hec_url: "https://splunk.example.com:8088/services/collector"
    hec_token: "${SPLUNK_HEC_TOKEN}"
    index: "opensase"
    source_type: "opensase:security"
```

### Elastic

```yaml
siem:
  elastic:
    enabled: true
    hosts:
      - "https://elastic.example.com:9200"
    api_key: "${ELASTIC_API_KEY}"
    index_pattern: "opensase-security"
```

### Microsoft Sentinel

```yaml
siem:
  sentinel:
    enabled: true
    workspace_id: "${SENTINEL_WORKSPACE_ID}"
    shared_key: "${SENTINEL_SHARED_KEY}"
    log_type: "OpenSASE"
```

### QRadar

```yaml
siem:
  qradar:
    enabled: true
    host: "qradar.example.com"
    api_token: "${QRADAR_TOKEN}"
    log_source_id: "opensase"
```

---

## SOAR Playbooks

### Playbook Structure

```yaml
playbook:
  id: malware-response
  name: "Malware Response"
  trigger:
    type: alert_type
    value: "MalwareDetected"
  steps:
    - id: enrich
      action: enrich_indicator
      params:
        types: [hash, ip]
      on_success: isolate
      
    - id: isolate
      action: isolate_device
      condition: "severity >= High"
      on_success: create_case
      
    - id: create_case
      action: create_case
      params:
        template: malware-incident
      on_success: notify
      
    - id: notify
      action: send_slack
      params:
        channel: "#security-alerts"
```

### Available Actions

| Category | Action | Description |
|----------|--------|-------------|
| **Enrichment** | enrich_indicator | Lookup in threat intel |
| **Response** | block_ip | Block IP at firewall |
| | isolate_device | Isolate via EDR |
| | disable_user | Disable in IdP |
| **Notification** | send_slack | Post to Slack |
| | send_email | Send email |
| | page_oncall | PagerDuty alert |
| **Ticketing** | create_ticket | Create Jira ticket |
| | create_case | Create SOC case |

---

## EDR Integrations

### Supported Platforms

| EDR | Capabilities |
|-----|--------------|
| **CrowdStrike** | Timeline, Processes, Network, Isolate |
| **Microsoft Defender** | Timeline, Processes, Isolate |
| **SentinelOne** | Timeline, Processes, Isolate |

### Configuration

```yaml
edr:
  crowdstrike:
    base_url: "https://api.crowdstrike.com"
    client_id: "${CS_CLIENT_ID}"
    client_secret: "${CS_CLIENT_SECRET}"
    
  defender:
    tenant_id: "${AZURE_TENANT_ID}"
    client_id: "${DEFENDER_CLIENT_ID}"
    client_secret: "${DEFENDER_CLIENT_SECRET}"
```

---

## Case Management

### Priority SLA

| Priority | Response Time | Resolution Time |
|----------|---------------|-----------------|
| P1 (Critical) | 15 minutes | 4 hours |
| P2 (High) | 1 hour | 8 hours |
| P3 (Medium) | 4 hours | 24 hours |
| P4 (Low) | 24 hours | 72 hours |

### Case Workflow

```
New → Triaged → InProgress → Containment → Eradication → Recovery → Closed
```

---

## Metrics & KPIs

| Metric | Description | Target |
|--------|-------------|--------|
| **MTTD** | Mean Time to Detect | < 5 min |
| **MTTR** | Mean Time to Respond | < 15 min |
| **MTTR-Resolve** | Mean Time to Resolve | < 4 hours |
| **SLA Compliance** | Cases within SLA | > 95% |

---

## Compliance Frameworks

### SOC 2 Type II

Controls mapped:
- CC6.1: Logical Access
- CC6.6: System Boundaries
- CC7.1: Detection
- CC7.2: Monitoring

### ISO 27001:2022

Controls mapped:
- A.5.1: Information Security Policies
- A.8.1: Access Control
- A.12.6: Vulnerability Management

### NIST CSF

Functions mapped:
- ID.AM: Asset Management
- PR.AC: Access Control
- DE.CM: Continuous Monitoring
- RS.RP: Response Planning

---

## Integration Targets

| Metric | Target |
|--------|--------|
| Event forwarding latency | < 1 second |
| Playbook execution | < 30 seconds |
| Auto-case creation | High severity |
| MTTR reduction | 50% improvement |
