# Email Security Gateway Architecture

## Overview

The OpenSASE Email Security Gateway (OESG) provides comprehensive email protection.

---

## Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                  EMAIL SECURITY GATEWAY                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SMTP/Milter ──► Connection Filter ──► Auth Validation          │
│                       │                      │                   │
│                       ▼                      ▼                   │
│              IP Reputation         SPF/DKIM/DMARC                │
│                       │                      │                   │
│                       └──────────┬───────────┘                   │
│                                  ▼                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              CONTENT ANALYSIS                               │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │ │
│  │  │ Spam    │  │ Phishing│  │ Attach  │  │  BEC    │       │ │
│  │  │ Bayes   │  │ URL/    │  │ Sandbox │  │ NLP/ML  │       │ │
│  │  │ +Rules  │  │ Brand   │  │ CDR     │  │         │       │ │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                  │                               │
│                                  ▼                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              DLP SCANNING (Outbound)                        │ │
│  │  Credit Cards │ SSN │ Confidential │ Custom Patterns        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                  │                               │
│                                  ▼                               │
│              VERDICT: Deliver │ Quarantine │ Reject             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Modules (10 modules, ~4,500 lines)

| Module | Lines | Purpose |
|--------|-------|---------|
| lib.rs | 500 | Core types, gateway service |
| parser.rs | 250 | MIME parsing, headers |
| spam.rs | 400 | Bayesian + heuristics |
| phishing.rs | 500 | URL, brand, typosquat |
| reputation.rs | 250 | IP/domain reputation |
| attachments.rs | 300 | File type, malware |
| sandbox.rs | 200 | Detonation analysis |
| bec.rs | 400 | Executive impersonation |
| dmarc.rs | 200 | SPF/DKIM/DMARC |
| dlp.rs | 350 | Data loss prevention |
| mta.rs | 250 | Milter integration |

---

## Detection Capabilities

### Spam Detection
- Bayesian classifier (trainable)
- Heuristic rules
- Keyword analysis
- Structure analysis

### Phishing Detection
- URL analysis
- Brand impersonation
- Typosquatting detection
- Credential harvesting

### Malware Detection
- File type detection
- Known hash lookup
- Sandbox detonation
- YARA matching

### BEC Detection
- VIP impersonation
- Financial keywords + urgency
- Gift card/wire transfer scams
- NLP sentiment analysis

### DLP
- Credit card (Luhn validated)
- SSN patterns
- Confidential keywords
- Custom regex patterns

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Spam Block Rate | 99.9% |
| False Positive Rate | <0.001% |
| Processing Time | <5 seconds |
| Throughput | 100K msgs/hour |

---

## Integration Points

| Component | Integration |
|-----------|-------------|
| MTA | Milter protocol, SMTP |
| Threat Intel | OSTIP IoC lookup |
| RBI | CDR sanitization |
| L7 Gateway | URL rewriting |
