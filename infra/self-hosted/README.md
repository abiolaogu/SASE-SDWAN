# OpenSASE Self-Hosted Platform Components

This directory contains deployment configurations for self-hosted alternatives to managed SaaS services, reducing operational costs and maintaining data sovereignty.

## Cost Comparison

| Category | SaaS Service | Self-Hosted | Monthly Savings |
|----------|-------------|-------------|-----------------|
| Monitoring | Datadog ($15/host) | VictoriaMetrics + Grafana | 70-80% |
| Logging | Splunk ($150/GB) | Loki + Grafana | 85-90% |
| Email | SendGrid ($90/100K) | Postal + Haraka | 90%+ |
| Registry | ECR ($0.10/GB) | Harbor | 60-70% |
| CI/CD | GitHub Actions | Woodpecker CI | 50-70% |
| Secrets | HashiCorp Vault Cloud | Self-hosted Vault | 80% |
| Storage | S3 ($0.023/GB) | MinIO | 40-60% |
| Messaging | Confluent Kafka | Redpanda | 70-80% |
| Database | RDS/Cloud SQL | YugabyteDB | 50-60% |
| Docs | Confluence ($6/user) | Outline | 90% |
| Project Mgmt | Jira ($8/user) | Plane | 85% |
| BI | Tableau ($70/user) | Apache Superset | 95% |
| API Gateway | Apigee ($10K/mo) | Kong/APISIX | 80-90% |

## Component Overview

### Monitoring (Prompt 60)
- **Stack**: VictoriaMetrics + Grafana + Alertmanager
- **Purpose**: Full Datadog/New Relic replacement
- **Capacity**: 1M+ metrics/sec

### Logging (Prompt 61)
- **Stack**: Grafana Loki + Promtail
- **Purpose**: Splunk replacement
- **Capacity**: 100TB+ retention

### Email (Prompt 62)
- **Stack**: Postal + Haraka MTA
- **Purpose**: SendGrid/Mailgun replacement
- **Capacity**: 1M+ emails/day

### Container Registry (Prompt 63)
- **Stack**: Harbor with Trivy scanning
- **Purpose**: ECR/Docker Hub replacement
- **Features**: Vulnerability scanning, replication

### CI/CD (Prompt 64)
- **Stack**: Woodpecker CI + GitOps
- **Purpose**: GitHub Actions replacement
- **Features**: Container-native, Kubernetes runners

### Secrets Management (Prompt 65)
- **Stack**: HashiCorp Vault (self-hosted)
- **Purpose**: Centralized secrets + PKI
- **Features**: Auto-unseal, HA, audit logging

### Object Storage (Prompt 66)
- **Stack**: MinIO
- **Purpose**: S3-compatible storage
- **Features**: Erasure coding, encryption

### Message Queue (Prompt 67)
- **Stack**: Redpanda
- **Purpose**: Kafka replacement
- **Features**: No ZooKeeper, lower latency

### Database (Prompt 68)
- **Stack**: YugabyteDB
- **Purpose**: Distributed PostgreSQL
- **Features**: Multi-region, auto-sharding

### Documentation (Prompt 71)
- **Stack**: Outline
- **Purpose**: Confluence/Notion replacement
- **Features**: Real-time collaboration

### Project Management (Prompt 72)
- **Stack**: Plane
- **Purpose**: Jira/Asana replacement
- **Features**: Open-source, self-hosted

### Business Intelligence (Prompt 73)
- **Stack**: Apache Superset
- **Purpose**: Tableau/Looker replacement
- **Features**: SQL editor, dashboards

### API Gateway (Prompt 74)
- **Stack**: Kong Gateway
- **Purpose**: See `sase-apigw` crate
- **Features**: Rate limiting, auth, transformation

## Deployment

Each component can be deployed via Kubernetes manifests or Docker Compose:

```bash
# Deploy monitoring stack
kubectl apply -f monitoring/

# Deploy via Helm
helm install monitoring ./monitoring/helm/
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Self-Hosted Platform                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │  Monitoring │ │   Logging   │ │   Secrets   │ │   Storage   ││
│  │ VictoriaM.  │ │    Loki     │ │    Vault    │ │    MinIO    ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
│                                                                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │   CI/CD     │ │  Registry   │ │  Database   │ │  Messaging  ││
│  │ Woodpecker  │ │   Harbor    │ │ YugabyteDB  │ │  Redpanda   ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
│                                                                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │    Docs     │ │  Projects   │ │     BI      │ │ API Gateway ││
│  │   Outline   │ │    Plane    │ │  Superset   │ │    Kong     ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```
