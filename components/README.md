# Custom SASE Components

This directory contains 4 proprietary-like components that emulate vendor SASE "secret sauce":

## Components

| Component | Description | Port |
|-----------|-------------|------|
| **UPO** | Unified Policy Orchestrator | 8090 |
| **QoE Selector** | QoE-based Path Selection | 8091 |
| **CASB-lite** | SaaS Visibility | 8092 |
| **DLP-lite** | Data Classification | 8093 |

## Quick Install

```bash
# Install all components
pip install -e components/upo
pip install -e components/qoe-selector
pip install -e components/casb-lite
pip install -e components/dlp-lite

# Or install with dev dependencies
pip install -e "components/upo[dev]"
```

## Component Details

### A) Unified Policy Orchestrator (UPO)

**Goal**: One intent policy → translated into per-system configs.

```bash
# Validate policy
upo validate policy.yaml

# Compile to target configs
upo compile policy.yaml --output /tmp/configs

# Apply to running systems
upo apply policy.yaml --dry-run
```

- Input: YAML intent (users, apps, segments, egress rules, inspection levels)
- Output adapters: OPNsense, OpenZiti, FlexiWAN
- [Full documentation](upo/README.md)

### B) QoE Path Selector

**Goal**: Choose best WAN path per app based on QoE metrics.

```bash
# Get recommendations
qoe-selector recommend --app-class voice

# Run simulation
qoe-selector simulate --scenario wan1-congestion
```

- Collects probes (latency, jitter, loss) per WAN link
- Computes scores per app class (voice, video, web, bulk)
- Simulator mode for demonstrations
- [Full documentation](qoe-selector/README.md)

### C) CASB-lite

**Goal**: Basic SaaS visibility without full vendor CASB.

```bash
# Sync from providers
casb-lite sync google-workspace
casb-lite sync microsoft-365

# Export to Wazuh
casb-lite export --destination wazuh
```

- Connectors for Google Workspace and Microsoft 365
- Pulls audit logs, risky sign-ins, user inventory
- Normalizes to common schema
- [Full documentation](casb-lite/README.md)

### D) DLP-lite

**Goal**: Basic data classification + alerting.

```bash
# List classifiers
dlp-lite classifiers list

# Scan content
dlp-lite scan --text "My SSN is 123-45-6789"
dlp-lite scan --file document.txt
```

- Classifier library: regex, checksum (Luhn), entropy
- Integration: proxy logs, endpoint file scan
- Exports alerts to Wazuh
- [Full documentation](dlp-lite/README.md)

## Demo Flow

Run the complete demo:

```bash
./scripts/demo-components.sh
```

This demonstrates:
1. Creating an intent policy
2. Compiling to target configurations
3. QoE path recommendations
4. CASB event ingestion
5. DLP content scanning
6. Dashboard integration

## API Servers

Start all component APIs:

```bash
# Each in a separate terminal
uvicorn upo.main:app --port 8090
uvicorn qoe_selector.main:app --port 8091
uvicorn casb_lite.main:app --port 8092
uvicorn dlp_lite.main:app --port 8093
```

## Docker Integration

Components can be added to `docker-compose.yml`:

```yaml
services:
  upo:
    build: ./components/upo
    ports:
      - "8090:8090"
    depends_on:
      - security-pop
      - ziti-controller
```
