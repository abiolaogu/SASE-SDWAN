# IOC Lifecycle Documentation

## Overview

Indicators of Compromise (IOCs) flow through a defined lifecycle from ingestion to expiration.

---

## IOC Lifecycle Stages

```
┌─────────────────────────────────────────────────────────────────┐
│                        IOC LIFECYCLE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. INGESTION         2. NORMALIZATION      3. DEDUPLICATION    │
│  ┌──────────┐         ┌──────────┐          ┌──────────┐        │
│  │ STIX/    │ ──────► │ Common   │ ──────►  │ Merge    │        │
│  │ TAXII    │         │ Schema   │          │ Sources  │        │
│  │ CSV/JSON │         │          │          │          │        │
│  └──────────┘         └──────────┘          └──────────┘        │
│                                                   │              │
│                                                   ▼              │
│  6. EXPIRATION        5. MATCHING           4. ENRICHMENT       │
│  ┌──────────┐         ┌──────────┐          ┌──────────┐        │
│  │ TTL      │ ◄────── │ Bloom    │ ◄──────  │ GeoIP    │        │
│  │ Cleanup  │         │ Filters  │          │ WHOIS    │        │
│  └──────────┘         └──────────┘          │ PassDNS  │        │
│                                              └──────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. Ingestion

| Source | Format | Poll Interval |
|--------|--------|---------------|
| STIX/TAXII | STIX 2.1 | 1 hour |
| AlienVault OTX | JSON | 30 min |
| Abuse.ch | CSV | 1 hour |
| VirusTotal | JSON | On-demand |
| MISP | JSON | 1 hour |

---

## 2. Normalization

All IOCs are normalized to a common schema:

```rust
struct Indicator {
    id: String,
    ioc_type: IocType,
    value: String,
    confidence: Confidence,
    severity: Severity,
    first_seen: DateTime,
    last_seen: DateTime,
    expires_at: Option<DateTime>,
    sources: Vec<IntelSource>,
    tags: Vec<String>,
    mitre_tactics: Vec<String>,
    mitre_techniques: Vec<String>,
}
```

---

## 3. Deduplication

When the same IOC arrives from multiple sources:
1. **Merge sources** - Track all contributing feeds
2. **Boost confidence** - Multiple sources = higher confidence
3. **Update timestamps** - Keep latest `last_seen`
4. **Merge tags** - Combine all labels

---

## 4. Enrichment

| Enrichment | IOC Types | Data Added |
|------------|-----------|------------|
| GeoIP | IP | Country, ASN, Org |
| WHOIS | Domain, IP | Registrar, dates |
| Passive DNS | Domain | Historical IPs |
| VirusTotal | All | Detection ratio |
| AbuseIPDB | IP | Abuse score |

---

## 5. Matching

**Performance Target: <1μs per lookup**

```
Lookup Request
     │
     ▼
┌────────────────┐
│ Bloom Filter   │ ─── No ──► Return: Clean
│ (0.1% FP)      │
└───────┬────────┘
        │ Maybe
        ▼
┌────────────────┐
│ Exact Lookup   │ ─── No ──► Return: Clean
│ (DashMap)      │
└───────┬────────┘
        │ Yes
        ▼
   Return: Match
```

---

## 6. Expiration

| Condition | Action |
|-----------|--------|
| TTL expired | Remove from active |
| No recent sightings (90d) | Demote confidence |
| Source revoked | Remove immediately |
| False positive | Whitelist |

---

## Confidence Scoring

| Sources | Confidence |
|---------|------------|
| 1 source | Source's default |
| 2 sources | Medium minimum |
| 3+ sources | High minimum |
| Confirmed | Manual verification |

---

## Distribution Targets

| IOC Type | Distributed To |
|----------|----------------|
| IP | XDP blocklist, DDoS Shield |
| Domain | L7 Gateway, DNS Sinkhole |
| URL | L7 Gateway |
| File Hash | IPS Engine |

---

## Retention Policy

| Severity | Active TTL | Archive TTL |
|----------|------------|-------------|
| Critical | 90 days | 1 year |
| High | 60 days | 6 months |
| Medium | 30 days | 3 months |
| Low | 14 days | 1 month |
