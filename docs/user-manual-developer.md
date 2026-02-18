# Developer Manual -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Developer Platform Overview

The OpenSASE Developer Platform (OSDP) provides REST APIs, SDKs, webhooks, a CLI tool, and IaC providers for automating all platform operations. From `api/src/lib.rs`, the architecture includes OpenAPI 3.1 documentation, OAuth 2.0 / API key authentication, and rate limiting.

## 2. Authentication

### 2.1 API Keys
Create an API key via the portal or API:
```bash
curl -X POST https://api.opensase.io/api/v1/api-keys \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-cd-key", "scopes": ["sites:read", "policies:write"], "expires_in_days": 90}'
```

Response from `api/src/models.rs` `ApiKeyCreated`:
```json
{
  "id": "uuid",
  "name": "ci-cd-key",
  "key": "os_live_abc123...",  // Only shown once
  "scopes": ["sites:read", "policies:write"]
}
```

### 2.2 OAuth 2.0
For user-facing applications, use Keycloak OIDC:
- Authorization URL: `http://localhost:8443/realms/opensase-lab/protocol/openid-connect/auth`
- Token URL: `http://localhost:8443/realms/opensase-lab/protocol/openid-connect/token`
- Client ID: `portal-app`

### 2.3 Rate Limits
From the OpenAPI spec (`opensase-core/docs/openapi/opensase-api.yaml`):

| Plan | Requests/min | Requests/day |
|------|-------------|-------------|
| Free | 60 | 10,000 |
| Pro | 600 | 100,000 |
| Enterprise | 6,000 | Unlimited |

## 3. API Reference

### 3.1 Base URL
```
https://api.opensase.io/api/v1
```

Swagger UI: `https://api.opensase.io/docs`

### 3.2 Core Endpoints

From `api/src/lib.rs` route structure:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/tenants/:id/users` | List users |
| POST | `/tenants/:id/users` | Create user |
| GET | `/tenants/:id/users/:id` | Get user |
| GET | `/tenants/:id/policies` | List policies |
| POST | `/tenants/:id/policies` | Create policy |
| GET | `/tenants/:id/sites` | List sites |
| POST | `/tenants/:id/sites` | Create site |
| GET | `/tenants/:id/tunnels` | List tunnels |
| GET | `/tenants/:id/tunnels/:id/stats` | Get tunnel stats |
| GET | `/tenants/:id/analytics/traffic` | Traffic stats |
| GET | `/tenants/:id/analytics/threats` | Threat stats |
| GET | `/tenants/:id/alerts` | List alerts |
| POST | `/webhooks` | Create webhook |
| POST | `/api-keys` | Create API key |

### 3.3 Response Format

All responses use the standard envelope from `api/src/models.rs`:
```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

Paginated responses:
```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "per_page": 20,
  "total_pages": 8
}
```

## 4. SDKs

### 4.1 Rust SDK
From `opensase-core/sdks/rust/lib.rs`:
```rust
use opensase_sdk::Client;

let client = Client::new("os_live_abc123...");
let sites = client.sites().list().await?;
let policy = client.policies().create(PolicyCreate {
    name: "block-tor".into(),
    description: "Block Tor exit nodes".into(),
    priority: 10,
    conditions: vec![PolicyCondition {
        field: "destination.category".into(),
        operator: "equals".into(),
        value: "tor-exit-node".into(),
    }],
    action: PolicyAction::Block,
}).await?;
```

### 4.2 Python SDK
From `opensase-core/sdks/python/__init__.py` and `sdk/python/opensase.py`:
```python
from opensase import OpenSASEClient

client = OpenSASEClient(api_key="os_live_abc123...")
sites = await client.sites.list()
policy = await client.policies.create(
    name="block-tor",
    description="Block Tor exit nodes",
    priority=10,
    action="block",
    conditions=[{"field": "destination.category", "operator": "equals", "value": "tor-exit-node"}]
)
```

### 4.3 Go SDK
From `opensase-core/sdks/go/opensase.go`:
```go
client := opensase.NewClient("os_live_abc123...")
sites, err := client.Sites.List(ctx)
```

### 4.4 TypeScript SDK
From `opensase-core/sdks/typescript/index.ts`:
```typescript
import { OpenSASE } from '@opensase/sdk';

const client = new OpenSASE({ apiKey: 'os_live_abc123...' });
const sites = await client.sites.list();
```

## 5. Webhooks

### 5.1 Creating a Webhook
```bash
curl -X POST https://api.opensase.io/api/v1/webhooks \
  -H "Authorization: Bearer os_live_abc123..." \
  -d '{"url": "https://your-app.com/webhook", "events": ["alert.created", "site.status_changed"]}'
```

### 5.2 Event Types
- `policy.updated` -- Policy created, updated, or deleted
- `site.status_changed` -- Site went online/offline/degraded
- `tunnel.status_changed` -- Tunnel up/down
- `alert.created` -- New security alert
- `user.created` -- New user added
- `edge.registered` -- New edge device registered

### 5.3 Webhook Payload
```json
{
  "event": "alert.created",
  "timestamp": "2026-02-17T10:30:00Z",
  "data": {
    "id": "uuid",
    "severity": "high",
    "message": "Potential DDoS attack detected",
    "source": "pop-nyc"
  },
  "signature": "sha256=abc123..."
}
```

### 5.4 Signature Verification
Verify webhook authenticity using HMAC-SHA256 with the webhook secret:
```python
import hmac, hashlib
expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
assert f"sha256={expected}" == signature_header
```

## 6. CLI Tool

### 6.1 Installation
From `cli/src/main.rs`:
```bash
cargo install opensase-cli
# or download binary from releases
```

### 6.2 Configuration
```bash
opensase config set api-url https://api.opensase.io
opensase config set api-key os_live_abc123...
```

### 6.3 Commands
From `cli/src/commands/`:
```bash
opensase sites list                    # List all sites
opensase sites create --name "NYC HQ"  # Create site
opensase policies list                 # List policies
opensase policies create -f policy.yaml # Create from file
opensase alerts list --severity high   # List high alerts
opensase analytics traffic --period 24h # Traffic stats
opensase users list                    # List users
```

## 7. Infrastructure as Code

### 7.1 Terraform Provider
From `terraform/opensase/main.go`:
```hcl
provider "opensase" {
  api_key = var.opensase_api_key
}

resource "opensase_site" "nyc" {
  name     = "NYC Headquarters"
  location = "New York, NY"
  timezone = "America/New_York"
}

resource "opensase_policy" "block_tor" {
  name        = "block-tor"
  description = "Block Tor exit nodes"
  priority    = 10
  action      = "block"
}
```

### 7.2 Ansible Collection
From `infra/ansible/`:
```yaml
- name: Deploy edge device
  opensase.edge.deploy:
    site_name: branch-nyc
    controller_url: https://api.opensase.io
    wan_interfaces:
      - name: wan1
        dhcp: true
```

## 8. Building from Source

### 8.1 Rust Components
```bash
cd opensase-core
cargo build --release       # Build all crates
cargo test                  # Run all tests
cargo bench                 # Run benchmarks
cargo fmt --check           # Check formatting
cargo clippy                # Lint
```

### 8.2 Portal Frontend
```bash
cd opensase-portal
npm install
npm run dev       # Development server
npm run build     # Production build
npm run test      # Run tests
npm run lint      # ESLint
```

### 8.3 Python Components
```bash
pip install -e components/upo
pip install -e components/qoe-selector
pip install -e components/casb-lite
pip install -e components/dlp-lite
cd components/upo && python -m pytest tests/ -v
```

## 9. Plugin Development

### 9.1 UPO Adapter Plugin
Create a new policy adapter for the Unified Policy Orchestrator:
```python
# components/upo/upo/adapters/custom.py
from upo.models import Policy, CompiledOutput, CompiledConfig

class CustomAdapter:
    name = "custom-firewall"

    def compile(self, policy: Policy) -> CompiledOutput:
        configs = []
        for rule in policy.access_rules:
            configs.append(CompiledConfig(
                target=self.name,
                config_type="firewall-rule",
                content={"action": rule.action.value, "users": rule.users}
            ))
        return CompiledOutput(adapter=self.name, policy_name=policy.name, configs=configs)
```

## 10. API Best Practices

1. Always use pagination for list endpoints (`?page=1&per_page=20`)
2. Subscribe to webhooks instead of polling for changes
3. Use API keys with minimal scopes (principle of least privilege)
4. Handle rate limit responses (HTTP 429) with exponential backoff
5. Validate webhook signatures before processing
6. Use idempotency keys for create operations
7. Cache frequently accessed data (sites, policies) client-side with TTL
