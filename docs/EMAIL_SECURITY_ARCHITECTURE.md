# Email Security Gateway Architecture

## Overview

The OpenSASE Email Security Gateway (OESG) provides comprehensive email protection.

---

## Inbound Email Flow

```
Internet MTA ──► [MX Record] ──► OpenSASE Email Gateway
                                        │
┌───────────────────────────────────────┴────────────────────────────────┐
│                         INBOUND PIPELINE                                │
│                                                                         │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐  │
│  │ Connect │──►│  Auth   │──►│  Anti-  │──►│ Threat  │──►│ Attach- │  │
│  │ Filter  │   │SPF/DKIM │   │  Spam   │   │ Intel   │   │ ment    │  │
│  │         │   │ /DMARC  │   │         │   │ Check   │   │ Sandbox │  │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘  │
│       │             │             │             │             │        │
│       ▼             ▼             ▼             ▼             ▼        │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐  │
│  │   URL   │──►│   BEC   │──►│ Content │──►│   DLP   │──►│  Final  │  │
│  │ Rewrite │   │ Detect  │   │ Policy  │   │ Outbnd  │   │ Verdict │  │
│  │ & Scan  │   │         │   │         │   │         │   │         │  │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘  │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
              ┌──────────────────────┴──────────────────────┐
              │               │               │              │
              ▼               ▼               ▼              ▼
         [DELIVER]      [QUARANTINE]     [REJECT]       [DROP]
        Customer MTA    Admin Review     SMTP 550      Silent
```

---

## Outbound Email Flow

```
Customer MTA ──► OpenSASE Email Gateway
                       │
┌──────────────────────┴──────────────────────┐
│            OUTBOUND PIPELINE                 │
│                                              │
│  • Rate Limiting (per sender/domain)         │
│  • DLP Scanning (PII, confidential)          │
│  • Sensitive Data Detection                  │
│  • DKIM Signing (RSA-SHA256)                 │
│  • TLS Policy Enforcement                    │
│  • Encryption (TLS/S-MIME)                   │
│                                              │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
                 Internet MTA
```

---

## Modules (14 modules, ~5,500 lines)

| Module | Lines | Purpose |
|--------|-------|---------|
| lib.rs | 500 | Core types, gateway |
| parser.rs | 250 | MIME parsing |
| mta.rs | 250 | Milter integration |
| spam.rs | 400 | Bayesian + rules |
| phishing.rs | 500 | URL + brand |
| reputation.rs | 250 | IP/domain scoring |
| attachments.rs | 300 | File analysis |
| sandbox.rs | 200 | Detonation |
| bec.rs | 400 | Executive fraud |
| dmarc.rs | 200 | Email auth |
| dlp.rs | 350 | Data loss prevention |
| urlrewrite.rs | 300 | Safe links |
| outbound.rs | 350 | DKIM + rate limiting |
| quarantine.rs | 350 | Message review |

---

## Protection Targets

| Metric | Target |
|--------|--------|
| Spam Block Rate | 99.9% |
| False Positive | <0.001% |
| Processing Time | <5s |
| Throughput | 100K msgs/hr |

---

## Integration Points

| Component | Integration |
|-----------|-------------|
| MTA | Milter protocol, SMTP |
| Threat Intel | OSTIP IoC lookup |
| RBI | CDR sanitization |
| L7 Gateway | URL rewriting |
| DLP | Pattern matching |
