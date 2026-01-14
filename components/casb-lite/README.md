# CASB-lite

Basic SaaS visibility without full vendor CASB.

## Overview

CASB-lite provides visibility into SaaS application usage by pulling audit logs from cloud providers and normalizing them to a common schema for SIEM integration.

## Requirements

### Functional
- Connectors for Google Workspace and Microsoft 365
- Pull audit logs, risky sign-ins, user/app inventory
- Normalize to common schema
- Export to Wazuh/OpenSearch

### Non-Goals
- Inline traffic inspection
- DLP integration (separate component)
- Real-time alerting (batch pull)
- Full shadow IT discovery

## Quick Start

```bash
# Install
pip install -e components/casb-lite

# Configure connectors
export GOOGLE_CREDENTIALS=/path/to/credentials.json
export MS365_CLIENT_ID=your-client-id
export MS365_CLIENT_SECRET=your-secret
export MS365_TENANT_ID=your-tenant-id

# List configured connectors
casb-lite connectors list

# Sync events
casb-lite sync google-workspace
casb-lite sync microsoft-365

# Export to Wazuh
casb-lite export --destination wazuh

# Start API server
casb-lite serve --port 8092
```

## Supported Connectors

| Provider | Events | Risky Sign-ins | User Inventory |
|----------|--------|----------------|----------------|
| Google Workspace | ✓ Admin audit, Login | ✓ Via alerts | ✓ Directory API |
| Microsoft 365 | ✓ Unified audit | ✓ Identity Protection | ✓ Graph API |

## Common Event Schema

All events are normalized to:

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "provider": "google-workspace",
  "event_type": "login",
  "user": "user@example.com",
  "source_ip": "192.168.1.1",
  "app": "Gmail",
  "action": "login_success",
  "risk_level": "low",
  "raw_event": {...}
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/connectors` | GET | List configured connectors |
| `/api/v1/sync/{connector}` | POST | Trigger sync |
| `/api/v1/events` | GET | Recent events |
| `/api/v1/risky-signins` | GET | Risky sign-in events |
| `/api/v1/users` | GET | User inventory |
| `/health` | GET | Health check |

## Limitations vs Full CASB

| Feature | CASB-lite | Full CASB |
|---------|-----------|-----------|
| Audit log ingestion | ✓ | ✓ |
| Risky sign-in detection | ✓ (provider-based) | ✓ (ML-enhanced) |
| Shadow IT discovery | ✗ | ✓ |
| Inline DLP | ✗ | ✓ |
| Encryption gateway | ✗ | ✓ |
| API rate limiting | Basic | Advanced |
| Real-time webhooks | ✗ | ✓ |
