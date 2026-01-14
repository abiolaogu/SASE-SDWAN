# OpenSASE Threat Intelligence Platform (OSTIP)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                   THREAT INTELLIGENCE PLATFORM                       │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │ STIX/TAXII  │  │    MISP     │  │  OpenCTI    │  │ Abuse.ch  │  │
│  │   Feeds     │  │   Feeds     │  │    API      │  │  Feeds    │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘  │
│         └─────────────────┴────────────────┴──────────────┘         │
│                                  │                                   │
│                                  ▼                                   │
│                    ┌─────────────────────────┐                      │
│                    │    Feed Aggregator      │                      │
│                    │  (Multi-format parser)  │                      │
│                    └───────────┬─────────────┘                      │
│                                │                                     │
│               ┌────────────────┼────────────────┐                   │
│               ▼                ▼                ▼                   │
│    ┌──────────────────┐ ┌────────────┐ ┌────────────────┐          │
│    │   Correlation    │ │ Enrichment │ │ MITRE ATT&CK  │          │
│    │     Engine       │ │   Engine   │ │   Mapper      │          │
│    └────────┬─────────┘ └─────┬──────┘ └───────┬────────┘          │
│             └─────────────────┼────────────────┘                    │
│                               ▼                                      │
│            ┌────────────────────────────────────────┐               │
│            │         IoC Database (10M+)            │               │
│            │  IPs | Domains | URLs | Hashes | CVEs  │               │
│            └───────────────────┬────────────────────┘               │
│                                │                                     │
│          ┌─────────────────────┼─────────────────────┐              │
│          ▼                     ▼                     ▼              │
│   ┌────────────┐       ┌────────────┐       ┌────────────┐         │
│   │    XDP     │       │   L7 GW    │       │    IPS     │         │
│   │ Blocklist  │       │ URL Filter │       │   Rules    │         │
│   └────────────┘       └────────────┘       └────────────┘         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## IoC Types Supported

| Type | Example | Distribution Target |
|------|---------|---------------------|
| IPv4/IPv6 | `192.168.1.1` | XDP, DDoS Shield |
| Domain | `malware.com` | L7 Gateway |
| URL | `https://phish.com/login` | L7 Gateway |
| File Hash | `SHA256:abc123...` | IPS Engine |
| Email | `attacker@evil.com` | L7 Gateway |
| CVE | `CVE-2024-1234` | IPS Rules |
| JA3/JARM | `abc123def...` | L7 Gateway |
| SSL Cert | `fingerprint` | L7 Gateway |

---

## Feed Sources

### Pre-configured
- **Abuse.ch URLhaus** - Malicious URLs
- **Abuse.ch Feodo Tracker** - Botnet C2
- **Abuse.ch SSL Blacklist** - Malicious SSL IPs

### Supported Formats
- STIX 2.1 / TAXII 2.1
- MISP
- OpenCTI (GraphQL)
- CSV
- JSON API
- RSS

---

## MITRE ATT&CK Integration

```
Indicator with C2 ThreatType
         │
         ▼
┌────────────────────────────┐
│ MITRE Mapper               │
│ ┌────────────────────────┐ │
│ │ Tactic: TA0011         │ │
│ │ (Command and Control)  │ │
│ ├────────────────────────┤ │
│ │ Technique: T1071       │ │
│ │ (App Layer Protocol)   │ │
│ └────────────────────────┘ │
└────────────────────────────┘
```

---

## Modules

| Module | Lines | Purpose |
|--------|-------|---------|
| `lib.rs` | 450 | Core types, ThreatIntelService |
| `feeds.rs` | 500 | Multi-source feed aggregator |
| `stix.rs` | 400 | STIX 2.1 / TAXII 2.1 client |
| `correlator.rs` | 300 | IoC correlation engine |
| `enrichment.rs` | 350 | Context enrichment (GeoIP, WHOIS) |
| `mitre.rs` | 350 | ATT&CK framework mapping |
| `distribution.rs` | 400 | Push to SASE components |

---

## Integration Points

| Component | Method | Data |
|-----------|--------|------|
| XDP/eBPF | REST API | IP blocklists |
| L7 Gateway | REST API | URL/domain filters |
| IPS Engine | REST API | File hash rules |
| DDoS Shield | REST API | High-severity IPs |

---

## Performance Targets

| Metric | Target |
|--------|--------|
| IoC Database Size | 10M+ indicators |
| Lookup Latency | <1ms (in-memory) |
| Feed Poll Interval | Configurable (1hr default) |
| Distribution Latency | <100ms |
