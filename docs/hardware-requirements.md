# Hardware Requirements -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Development/Lab Environment

### 1.1 Full Profile (Docker Compose)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 16 GB | 32 GB |
| Disk | 20 GB SSD | 50 GB NVMe |
| Network | 1 Gbps | 10 Gbps |
| OS | Linux (Docker 24.0+) | Ubuntu 22.04 / macOS 14+ |

From `README.md`: Full profile runs 20+ containers including FlexiWAN, OpenZiti, Wazuh, Keycloak, Prometheus, Grafana, and Portal.

### 1.2 Lite Profile

From `docker-compose.lite.yml`:

| Resource | Minimum |
|----------|---------|
| CPU | 4 cores |
| RAM | 8 GB |
| Disk | 15 GB SSD |

Lite profile reduces: Wazuh Indexer (1GB heap), Wazuh Manager (1GB limit), Prometheus (512MB, 1-day retention), Grafana (256MB), Keycloak (768MB), FlexiWAN Controller (512MB).

## 2. PoP Server Specifications

### 2.1 Small PoP (10 Gbps)

| Component | Specification |
|-----------|--------------|
| CPU | Intel Xeon E-2388G (8C/16T, 3.2 GHz) |
| RAM | 64 GB DDR4 ECC |
| NIC | Intel X710 10GbE dual-port |
| Storage | 2x 960 GB NVMe (RAID-1) |
| Power | 500W redundant PSU |
| Chassis | 1U rackmount |

Supports: 1,000 tunnels, 100K concurrent sessions, basic security stack.

### 2.2 Medium PoP (40 Gbps)

| Component | Specification |
|-----------|--------------|
| CPU | AMD EPYC 7543P (32C/64T, 2.8 GHz) |
| RAM | 256 GB DDR4 ECC |
| NIC | Mellanox ConnectX-6 Dx 25GbE dual-port |
| Storage | 4x 1.92 TB NVMe (RAID-10) |
| Power | 800W redundant PSU |
| Chassis | 2U rackmount |

Supports: 5,000 tunnels, 500K concurrent sessions, full security stack with ML inference.

### 2.3 Large PoP (100 Gbps)

| Component | Specification |
|-----------|--------------|
| CPU | 2x AMD EPYC 9654 (96C/192T, 2.4 GHz) |
| RAM | 512 GB DDR5 ECC |
| NIC | Mellanox ConnectX-7 100GbE dual-port |
| Storage | 8x 3.84 TB NVMe (RAID-10) |
| GPU (optional) | NVIDIA A10 (for ML inference) |
| Power | 2x 1600W redundant PSU |
| Chassis | 2U rackmount |

Supports: 10,000 tunnels, 10M concurrent sessions, VPP/DPDK at 100 Gbps.

VPP requirements from `opensase-core/vpp/scripts/setup_hugepages.sh`:
- Hugepages: 16 GB (2MB pages) or 8 GB (1GB pages)
- Dedicated CPU cores: 8-16 cores isolated from OS scheduler
- IOMMU enabled for DPDK NIC binding

## 3. Edge Appliance Specifications

### 3.1 Small Branch (< 50 users)

| Component | Specification |
|-----------|--------------|
| Form Factor | Mini PC (e.g., Intel NUC) |
| CPU | Intel Core i3-1315U (6C, 1.2 GHz) |
| RAM | 8 GB DDR4 |
| Storage | 128 GB NVMe |
| WAN | 2x 1 GbE RJ45 |
| LAN | 1x 1 GbE RJ45 |
| LTE (optional) | 4G/5G modem module |
| Power | 65W DC adapter |

Runs: `opensase-edge` binary, WireGuard tunnel, local firewall.

### 3.2 Medium Branch (50-200 users)

| Component | Specification |
|-----------|--------------|
| Form Factor | Desktop appliance (e.g., Protectli Vault) |
| CPU | Intel Core i5-1340P (12C, 1.9 GHz) |
| RAM | 16 GB DDR4 |
| Storage | 256 GB NVMe |
| WAN | 2x 2.5 GbE RJ45 |
| LAN | 2x 2.5 GbE RJ45 |
| LTE | 5G modem module |
| Wi-Fi (optional) | Wi-Fi 6E |
| Power | 90W DC adapter |

Runs: `opensase-edge` with local IPS, DLP scanning, HA support.

### 3.3 Large Branch / Data Center (200+ users)

| Component | Specification |
|-----------|--------------|
| Form Factor | 1U rackmount |
| CPU | Intel Xeon D-2776NT (16C, 2.1 GHz) |
| RAM | 64 GB DDR5 ECC |
| Storage | 2x 480 GB NVMe (RAID-1) |
| WAN | 2x 10 GbE SFP+ |
| LAN | 4x 10 GbE SFP+ |
| LTE | Dual 5G modem |
| Power | 150W redundant DC |

Runs: Full `opensase-edge` with XDP acceleration, dual-WAN bonding, HA pair.

## 4. Cloud/Virtual Requirements

### 4.1 AWS EC2

| PoP Size | Instance Type | vCPUs | RAM | Network |
|----------|--------------|-------|-----|---------|
| Small | c6i.2xlarge | 8 | 16 GB | 12.5 Gbps |
| Medium | c6i.8xlarge | 32 | 64 GB | 12.5 Gbps |
| Large | c6i.metal | 128 | 256 GB | 100 Gbps (ENA) |

From `infra/hyperscaler/aws/user_data.sh`.

### 4.2 Harvester HCI (Self-Hosted)

From `opensase-core/k8s/harvester-config.yaml`:

| Resource | Minimum (3-node cluster) |
|----------|------------------------|
| CPU per node | 16 cores |
| RAM per node | 128 GB |
| Storage per node | 4x 1 TB NVMe |
| Network per node | 2x 25 GbE |
| Total cluster | 48 cores, 384 GB RAM |

### 4.3 Kubernetes Node Requirements

From `infra/k8s/services/opensase-control-plane.yaml`:

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-----------|-----------|----------------|--------------|
| API Server | 500m | 2000m | 1 Gi | 4 Gi |
| Portal | 200m | 1000m | 512 Mi | 2 Gi |
| VPP Gateway | 100m | 1000m | 256 Mi | 1 Gi |

## 5. Network Requirements

### 5.1 PoP Connectivity

| Link | Bandwidth | Latency | Purpose |
|------|-----------|---------|---------|
| Internet uplink | 10-100 Gbps | < 5ms to IXP | User traffic |
| Backbone (inter-PoP) | 10-100 Gbps | < 50ms | ClusterMesh |
| Management | 1 Gbps | N/A | OOB access |

### 5.2 Branch Connectivity

| Link | Bandwidth | Latency | Purpose |
|------|-----------|---------|---------|
| WAN1 (primary) | 100 Mbps - 10 Gbps | < 50ms to PoP | Primary tunnel |
| WAN2 (backup) | 50 Mbps - 1 Gbps | < 100ms | Failover |
| LTE (failover) | 50-500 Mbps | < 100ms | Last resort |

## 6. Storage Requirements

### 6.1 Per-PoP Storage

| Data | Size (1000 sites) | Growth Rate |
|------|-------------------|-------------|
| YugabyteDB (operational) | 50 GB | 5 GB/month |
| ScyllaDB (sessions/flows) | 500 GB | 100 GB/month |
| ClickHouse (analytics) | 200 GB | 50 GB/month |
| Quickwit (logs) | 1 TB | 200 GB/month |
| Wazuh (SIEM) | 500 GB | 100 GB/month |
| Prometheus (metrics) | 50 GB | 10 GB/month (7-day retention) |
| Container images | 20 GB | Stable |
| **Total** | **~2.3 TB** | **~465 GB/month** |

## 7. Environmental Requirements

| Parameter | Requirement |
|-----------|------------|
| Operating temperature | 10-35 C (PoP), 0-45 C (edge) |
| Humidity | 20-80% non-condensing |
| Power | 200-240V AC, 50/60 Hz (PoP) |
| UPS | 30 minutes runtime minimum |
| Cooling | 2-5 kW per rack (PoP) |
