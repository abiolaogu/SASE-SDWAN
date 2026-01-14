# OpenSASE Layer 7 Gateway Documentation

## Overview

The OpenSASE Layer 7 Gateway (OL7G) provides enterprise-grade security services:

| Service | Description | Performance |
|---------|-------------|-------------|
| **SWG** | Secure Web Gateway | 20 Gbps |
| **CASB** | Cloud Access Security Broker | 5 Gbps |
| **ZTNA** | Zero Trust Network Access | 10K users |
| **DLP** | Data Loss Prevention | 10 Gbps |

## Architecture

```
Internet ──▶ Envoy (TLS) ──▶ WASM Filters ──▶ Upstream
              │                   │
              │  ┌────────────────┴────────────────┐
              │  │ URL Filter │ DLP │ CASB │ AuthN │
              │  └────────────────────────────────┘
              │
              └──▶ xDS Control Plane (gRPC)
```

## Quick Start

```bash
# Generate certificates
./scripts/generate-certs.sh

# Build WASM filters
cargo build --target wasm32-wasi --release -p sase-envoy-filters
cp target/wasm32-wasi/release/*.wasm envoy/wasm/

# Start the gateway
docker-compose -f envoy/docker-compose.yaml up -d
```

## Configuration

### URL Filtering (SWG)

```yaml
blocked_categories:
  - malware
  - phishing
  - gambling
  - adult

allowed_domains:
  - company.com
  - partner.example.com
```

### CASB Policies

```yaml
saas_apps:
  microsoft365:
    allowed: true
    dlp: true
    require_mfa: false
  
  dropbox:
    allowed: false

  github:
    allowed: true
    allowed_actions:
      - read
      - write
    blocked_actions:
      - admin
```

### DLP Patterns

```yaml
patterns:
  - SSN           # Social Security Numbers
  - CREDIT_CARD   # Credit card numbers
  - API_KEY       # API keys/secrets
  - AWS_KEY       # AWS access keys
  - PRIVATE_KEY   # Private keys

action: block  # or: redact, alert, log
```

## ZTNA Configuration

```yaml
# Private application access
apps:
  - name: internal-dashboard
    host: internal-dashboard.private:8080
    path: /app/internal-dashboard
    require_mfa: true
    
  - name: erp
    host: erp.private:443
    path: /app/erp
    require_mfa: true
    allowed_groups:
      - finance
      - hr
```

## Monitoring

### Prometheus Metrics

- `envoy_http_downstream_rq_total` - Total requests
- `envoy_http_downstream_rq_xx` - Response codes
- `envoy_cluster_upstream_rq_time` - Upstream latency
- `opensase_url_filter_blocked` - Blocked URLs
- `opensase_dlp_violations` - DLP violations
- `opensase_casb_blocked` - CASB blocks

### Grafana Dashboards

Access at `http://localhost:3000`:
- **Gateway Overview** - Traffic, latency, error rates
- **Security Events** - Blocks, alerts, DLP violations
- **CASB Analytics** - SaaS usage, shadow IT

## Performance Tuning

### Envoy Settings

```yaml
# Connection limits
listener:
  connection_limit: 100000

# HTTP/2
http2_protocol_options:
  max_concurrent_streams: 1000
```

### Resource Allocation

```yaml
deploy:
  resources:
    limits:
      cpus: "8"
      memory: 16G
```

## Troubleshooting

```bash
# Check Envoy health
curl http://localhost:9901/ready

# View access logs
docker logs -f opensase-envoy

# Test URL filter
curl -x https://localhost:443 http://malware-test.com
```
