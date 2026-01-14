# QoE Path Selector

Proprietary-like SD-WAN path selection based on Quality of Experience metrics.

## Overview

The QoE Path Selector chooses the optimal WAN path for each application class based on:
- **Latency**: Round-trip time
- **Jitter**: Latency variation
- **Loss**: Packet loss percentage
- **Bandwidth**: Available capacity

## Requirements

### Functional
- Collect probes (ping/HTTP) per WAN link per site
- Compute weighted scores per app class (voice, video, web, bulk)
- Emit steering recommendations for SD-WAN layer
- Simulator mode for demonstrations

### Non-Goals
- Real packet steering (recommendation only)
- Sub-second failover
- Hardware appliance integration

## Quick Start

```bash
# Install
pip install -e components/qoe-selector

# Run probes
qoe-selector probe --sites branch-a,branch-b

# Get recommendations
qoe-selector recommend --app-class voice

# Run simulator
qoe-selector simulate --scenario congestion

# Start API server
qoe-selector serve --port 8091
```

## App Classes & Thresholds

| Class | Max Latency | Max Jitter | Max Loss | Weight |
|-------|-------------|------------|----------|--------|
| Voice | 150ms | 30ms | 1% | Latency:0.5, Jitter:0.3, Loss:0.2 |
| Video | 200ms | 50ms | 2% | Latency:0.4, Jitter:0.3, Loss:0.3 |
| Web | 500ms | 100ms | 5% | Latency:0.6, Loss:0.3, BW:0.1 |
| Bulk | 1000ms | 200ms | 5% | BW:0.7, Latency:0.2, Loss:0.1 |

## Scoring Algorithm

```
Score = Σ(weight[metric] × normalize(metric_value))

Where:
- normalize(latency) = max(0, 1 - (latency / max_latency))
- normalize(jitter) = max(0, 1 - (jitter / max_jitter))
- normalize(loss) = max(0, 1 - (loss / max_loss))
- normalize(bandwidth) = min(1, bandwidth / target_bandwidth)
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/probes` | GET | Current probe results |
| `/api/v1/probes/{site}` | GET | Probes for specific site |
| `/api/v1/scores` | GET | Computed path scores |
| `/api/v1/recommendations` | GET | Steering recommendations |
| `/api/v1/simulate` | POST | Run simulation scenario |
| `/health` | GET | Health check |

## Simulator Scenarios

```bash
# Normal operation
qoe-selector simulate --scenario normal

# WAN1 congestion
qoe-selector simulate --scenario wan1-congestion

# WAN2 failure
qoe-selector simulate --scenario wan2-failure

# Variable quality
qoe-selector simulate --scenario variable --duration 60
```

## Integration with FlexiWAN

Recommendations are emitted as routing policy updates:

```json
{
  "site": "branch-a",
  "app_class": "voice",
  "recommendation": {
    "primary_path": "wan1",
    "backup_path": "wan2",
    "reason": "wan1 has lower latency (15ms vs 45ms)"
  }
}
```
