# OpenSASE Email Security Gateway (OESG)

## MTA Deployment Guide

### Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                     OESG EMAIL FLOW                                        │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Internet ──► MX Records ──► OESG SMTP Server (Port 25)                   │
│                                        │                                   │
│                                        ▼                                   │
│                          ┌─────────────────────────┐                       │
│                          │   CONNECTION FILTER     │                       │
│                          │  • Rate limiting        │                       │
│                          │  • IP reputation        │                       │
│                          │  • DNS blocklists       │                       │
│                          └───────────┬─────────────┘                       │
│                                      ▼                                     │
│                          ┌─────────────────────────┐                       │
│                          │   AUTHENTICATION        │                       │
│                          │  • SPF validation       │                       │
│                          │  • DKIM verification    │                       │
│                          │  • DMARC evaluation     │                       │
│                          └───────────┬─────────────┘                       │
│                                      ▼                                     │
│            ┌──────────────┬──────────┴──────────┬──────────────┐           │
│            ▼              ▼                     ▼              ▼           │
│   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│   │ Anti-Spam   │ │ Phishing    │ │ Attachment  │ │    BEC      │         │
│   │ (Bayesian)  │ │ Detection   │ │  Sandbox    │ │ Detection   │         │
│   └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘         │
│          └───────────────┴───────────────┴───────────────┘                 │
│                                      │                                     │
│                                      ▼                                     │
│                          ┌─────────────────────────┐                       │
│                          │    VERDICT ENGINE       │                       │
│                          │  Deliver / Quarantine   │                       │
│                          │      / Reject           │                       │
│                          └───────────┬─────────────┘                       │
│                                      │                                     │
│                   ┌──────────────────┼──────────────────┐                  │
│                   ▼                  ▼                  ▼                  │
│            ┌──────────┐      ┌──────────────┐   ┌──────────────┐          │
│            │ DELIVER  │      │ QUARANTINE   │   │   REJECT     │          │
│            │ to MTA   │      │ for Review   │   │   at SMTP    │          │
│            └──────────┘      └──────────────┘   └──────────────┘          │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## SMTP Server Configuration

```rust
SmtpConfig {
    listen_addr: "0.0.0.0:25",
    hostname: "mail.example.com",
    max_message_size: 50 * 1024 * 1024,  // 50MB
    max_recipients: 100,
    timeout_seconds: 300,
    require_tls: true,
    rate_limits: RateLimitConfig {
        connections_per_ip: 50,
        messages_per_connection: 100,
        window_seconds: 60,
    },
}
```

---

## Detection Targets

| Threat | Detection Rate | False Positive |
|--------|----------------|----------------|
| Spam | 99.9% | <0.001% |
| Phishing | 99.5% | <0.01% |
| BEC | 95% | <0.1% |
| Malware | 99% | <0.001% |

---

## Module Summary (18 modules)

### Core
| Module | Lines | Purpose |
|--------|-------|---------|
| lib.rs | 500 | Core types |
| smtp.rs | 450 | SMTP server |
| pipeline.rs | 300 | Orchestration |

### Authentication
| Module | Purpose |
|--------|---------|
| auth.rs | SPF/DKIM/DMARC |
| dmarc.rs | DMARC policy |

### Content Analysis
| Module | Purpose |
|--------|---------|
| spam.rs | Bayesian + rules |
| phishing.rs | URL + brand |
| bec.rs | Executive fraud |
| blocklists.rs | DNS RBL |

### Attachments
| Module | Purpose |
|--------|---------|
| attachments.rs | Static analysis |
| sandbox.rs | Basic sandbox |
| sandbox_advanced.rs | YARA + behavioral |

### URL Protection
| Module | Purpose |
|--------|---------|
| urlrewrite.rs | Safe links |
| parser.rs | MIME parsing |

### Outbound
| Module | Purpose |
|--------|---------|
| outbound.rs | DKIM + rate |
| dlp.rs | Data loss |
| mta.rs | Milter |

### Admin
| Module | Purpose |
|--------|---------|
| quarantine.rs | Message review |
| reputation.rs | Sender scoring |

---

## Docker Deployment

```yaml
version: '3.8'
services:
  oesg:
    image: opensase/email-gateway:latest
    ports:
      - "25:25"
      - "587:587"
      - "465:465"
    environment:
      - OESG_HOSTNAME=mail.example.com
      - OESG_ENABLE_TLS=true
      - OESG_SANDBOX_ENABLED=true
    volumes:
      - ./certs:/certs:ro
      - ./quarantine:/var/quarantine
```

---

## Integration with MTA

### Postfix Integration (milter)
```
# /etc/postfix/main.cf
smtpd_milters = inet:oesg:8891
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
```

### Haraka Integration (plugin)
```javascript
exports.hook_data_post = function(next, connection) {
    // Forward to OESG for scanning
    connection.transaction.message_stream.pipe(oesg_client);
};
```
