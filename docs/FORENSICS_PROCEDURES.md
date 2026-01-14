# Digital Forensics Procedures

## Overview

This guide covers forensic evidence collection procedures using OpenSASE OSOP with integrated EDR platforms.

---

## Chain of Custody

### Evidence Handling Requirements

1. **Identification** - Unique ID for each evidence item
2. **Collection** - Documented collection process
3. **Preservation** - Tamper-evident storage
4. **Analysis** - Documented analysis steps
5. **Presentation** - Court-admissible format

### Evidence Hash Verification

All evidence is hashed with SHA-256:

```
Evidence ID: EVD-2024-001
SHA-256: a3f2b8c9d4e5f6...
Collected: 2024-01-15T10:30:00Z
Collector: analyst@example.com
```

---

## Collection Scopes

### Triage Collection (Fast)

| Artifact | Source | Time |
|----------|--------|------|
| Process list | EDR | < 1 min |
| Network connections | EDR | < 1 min |
| Recent files | EDR | < 5 min |
| Event logs (24h) | SIEM | < 5 min |

### Standard Collection

| Artifact | Source | Time |
|----------|--------|------|
| Full timeline (7d) | EDR | 10-30 min |
| Registry hives | EDR | 5-10 min |
| Prefetch files | EDR | 5 min |
| Browser artifacts | EDR | 10 min |
| Network capture | TAP | Continuous |

### Full Collection (Critical Incidents)

| Artifact | Source | Time |
|----------|--------|------|
| Memory dump | EDR | 15-60 min |
| Disk image | EDR/Manual | 1-4 hours |
| All logs (30d) | SIEM | 30 min |
| Email archives | O365/GSuite | Variable |

---

## EDR Collection Commands

### CrowdStrike

```json
{
  "action": "collect_forensics",
  "device_id": "abc123",
  "artifacts": [
    "ProcessList",
    "NetworkConnections",
    "AutoRuns",
    "DNSCache",
    "FileTimeline"
  ],
  "time_range": {
    "hours": 72
  }
}
```

### Microsoft Defender

```json
{
  "action": "collect_investigation_package",
  "machine_id": "def456",
  "comment": "Incident INV-2024-001"
}
```

### SentinelOne

```json
{
  "action": "fetch_files",
  "agent_id": "ghi789",
  "paths": [
    "C:/Windows/System32/config",
    "C:/Users/*/AppData/Local/Temp"
  ]
}
```

---

## Memory Analysis

### Collection via EDR

```yaml
forensics:
  memory_dump:
    device_id: ${device_id}
    format: raw
    compress: true
    hash: true
```

### Analysis Tools

| Tool | Purpose |
|------|---------|
| Volatility 3 | Memory forensics framework |
| Rekall | Memory analysis |
| Strings | Extract text |

### Key Artifacts

- Running processes
- Network connections
- Loaded DLLs
- Registry in memory
- Encryption keys
- Malware in memory

---

## Disk Image Collection

### Live Acquisition

```yaml
forensics:
  disk_image:
    device_id: ${device_id}
    method: live  # live or offline
    format: e01   # e01 or raw
    compress: true
    verify: true
```

### Verification

```
Source Hash: sha256:a1b2c3...
Image Hash:  sha256:a1b2c3...
Status: VERIFIED
```

---

## Network Forensics

### Packet Capture

```yaml
forensics:
  network_capture:
    filter: "host ${ip_address}"
    duration: 3600  # 1 hour
    format: pcapng
    interfaces:
      - eth0
      - tap0
```

### Flow Analysis

```yaml
forensics:
  flow_analysis:
    source_ip: ${source_ip}
    time_range:
      start: "2024-01-15T00:00:00Z"
      end: "2024-01-15T23:59:59Z"
    export: csv
```

---

## Log Collection

### SIEM Query

```spl
# Splunk
index=security sourcetype=* host=${hostname}
| earliest=-7d latest=now
| table _time, source, sourcetype, _raw
```

```kql
# Sentinel
SecurityEvent
| where Computer == "${hostname}"
| where TimeGenerated > ago(7d)
| project TimeGenerated, EventID, Activity, Account
```

### Log Types

| Log | Location | Retention |
|-----|----------|-----------|
| Windows Security | Event Log | 90 days |
| Windows System | Event Log | 90 days |
| Sysmon | Event Log | 30 days |
| PowerShell | Event Log | 30 days |
| Firewall | SIEM | 1 year |
| Proxy | SIEM | 1 year |
| DNS | SIEM | 90 days |

---

## Analysis Procedures

### Timeline Analysis

1. Collect all timestamps
2. Normalize to UTC
3. Correlate events
4. Identify patterns
5. Document findings

### Indicator Extraction

```yaml
iocs:
  - type: ip
    value: "192.0.2.1"
    context: "C2 communication"
    
  - type: hash
    algorithm: sha256
    value: "a1b2c3..."
    context: "Malware sample"
    
  - type: domain
    value: "evil.example.com"
    context: "Phishing domain"
```

---

## Reporting Template

```markdown
# Forensic Analysis Report

## Executive Summary
Brief overview of findings

## Incident Details
- Case ID: ${case_id}
- Classification: ${case_type}
- Severity: ${severity}

## Evidence Collected
| ID | Type | Source | Hash |
|----|------|--------|------|
| EVD-001 | Memory | Host-A | sha256:... |

## Timeline of Events
Chronological sequence...

## Technical Findings
Detailed analysis...

## Indicators of Compromise
List of IOCs...

## Recommendations
Actions to take...

## Appendix
Supporting data...
```

---

## Legal Considerations

### Evidence Preservation

- Document collection methodology
- Maintain chain of custody
- Use forensic tools with court acceptance
- Hash all evidence
- Store in tamper-evident format

### Privacy

- Follow data protection regulations
- Limit collection to relevant data
- Anonymize PII when possible
- Document legal basis for collection
