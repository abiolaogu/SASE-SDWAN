# OpenSASE-Lab 🛡️

A fully reproducible **SASE (Secure Access Service Edge)** security lab that implements enterprise-grade SD-WAN, ZTNA, IPS, and SIEM—all running locally via Docker Compose.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-%3E%3D24.0-blue.svg)
![Status](https://img.shields.io/badge/status-lab--ready-green.svg)

## 🎯 What's Included

| Component | Technology | Purpose |
|-----------|------------|---------|
| **SD-WAN** | FlexiWAN | WireGuard-based overlay networking with 3 branch sites |
| **Security PoP** | Suricata + Unbound | IPS/IDS and secure DNS with policy enforcement |
| **ZTNA** | OpenZiti | Zero Trust access to private apps (no public ports) |
| **SIEM** | Wazuh | Centralized security visibility and alerting |
| **SSO** | Keycloak | OIDC identity provider for all services |
| **Observability** | Prometheus + Grafana | Metrics and dashboards |
| **Portal** | FastAPI + React | Unified "single pane of glass" dashboard |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security PoP (Hub)                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ FlexiWAN │ │ OpenZiti │ │ Suricata │ │  Wazuh   │        │
│  │Controller│ │Controller│ │   IPS    │ │ Manager  │        │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
│                   ┌─────────┐ ┌─────────┐                    │
│                   │Keycloak │ │ Portal  │                    │
│                   └─────────┘ └─────────┘                    │
└───────────────────────┬─────────────────────────────────────┘
                        │ WireGuard + Ziti Fabric
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │Branch A │    │Branch B │    │Branch C │
    │  App1   │    │  App2   │    │         │
    │(private)│    │(private)│    │         │
    └─────────┘    └─────────┘    └─────────┘
```

## ⚡ Quick Start

### Prerequisites

- Docker Engine 24.0+ with Compose V2
- 16GB RAM (8GB for lite mode)
- 20GB free disk space
- Ports: 3000, 3001, 5601, 8080, 8443 available

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/opensase-lab.git
cd opensase-lab

# Create environment file
cp .env.example .env

# Edit secrets (REQUIRED!)
nano .env  # Change all 'changeme_*' values

# Start the lab
make up

# Check status
make status

# Run smoke tests
make smoke-test
```

### Lite Mode (8GB RAM)

```bash
make lite
```

## 🔗 Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| **Unified Portal** | http://localhost:8080 | Keycloak SSO |
| **FlexiWAN** | http://localhost:3000 | .env credentials |
| **Grafana** | http://localhost:3001 | admin / (see .env) |
| **Wazuh Dashboard** | http://localhost:5601 | wazuh-wui / (see .env) |
| **Keycloak Admin** | http://localhost:8443 | admin / (see .env) |
| **Prometheus** | http://localhost:9090 | - |

### Default Portal Users

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Full access |
| operator | operator123 | Manage |
| viewer | viewer123 | Read-only |

## 📋 Makefile Commands

```bash
make up          # Start all services (full profile)
make lite        # Start in lite mode (8GB RAM)
make down        # Stop all services
make smoke-test  # Run automated validation
make demo        # Interactive walkthrough
make status      # Show service status
make logs        # Tail all logs
make clean       # Remove all data (with confirmation)
```

### Individual Components

```bash
make up-sdwan       # SD-WAN only
make up-security    # Security PoP only
make up-ztna        # OpenZiti only
make up-siem        # Wazuh only
make up-portal      # Portal + Keycloak
make up-observability  # Prometheus + Grafana
```

## 📁 Repository Structure

```
opensase-lab/
├── Makefile                 # All automation targets
├── docker-compose.yml       # Main orchestration
├── docker-compose.lite.yml  # Reduced resources
├── .env.example             # Environment template
│
├── docker/
│   ├── flexiwan-controller/ # SD-WAN controller
│   ├── flexiwan-edge/       # Branch edge configs
│   ├── security-pop/        # Suricata + Unbound
│   ├── openziti-*/          # ZTNA components
│   ├── wazuh/               # SIEM stack
│   ├── keycloak/            # Identity provider
│   ├── prometheus/          # Metrics collection
│   └── grafana/             # Dashboards
│
├── portal/
│   ├── backend/             # FastAPI aggregator
│   └── frontend/            # React dashboard
│
├── scripts/
│   ├── generate-configs.sh  # Config generation
│   ├── smoke-test.sh        # Automated tests
│   └── demo.sh              # Interactive demo
│
├── docs/
│   ├── ARCHITECTURE.md      # Detailed architecture
│   ├── THREAT_MODEL.md      # Security analysis
│   ├── OPS_RUNBOOK.md       # Operations guide
│   └── PERFORMANCE_NOTES.md # Tuning guide
│
└── k8s/                     # Future Helm charts
```

## 🔒 Security Features

### Zero Trust (OpenZiti)
- **Dark services**: Apps have no public IP or ports
- **mTLS everywhere**: End-to-end encryption
- **Identity-based access**: Policies tied to enrolled identities
- **Posture checks**: Device health validation

### IPS/IDS (Suricata)
- Inline IPS mode with ET Open rules
- Custom rules for lab scenarios
- EVE JSON logging to Wazuh
- Automatic rule updates

### SIEM (Wazuh)
- Centralized log collection
- Suricata alert correlation
- File integrity monitoring
- Vulnerability detection

## 📊 Smoke Tests

The lab includes automated validation for:

| Test | Description |
|------|-------------|
| T1 | SD-WAN overlay ping between sites |
| T2 | ZTNA access to App1 in Branch A |
| T3 | ZTNA access to App2 in Branch B |
| T4 | Suricata IPS mode verification |
| T5 | IPS logging to eve.json |
| T6 | Wazuh agent registration |
| T7 | Wazuh alert generation |
| T8 | Keycloak health check |
| T9 | Portal API health |

Run with: `make smoke-test`

## 📖 Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) - Detailed design with Mermaid diagrams
- [Threat Model](docs/THREAT_MODEL.md) - STRIDE analysis and mitigations
- [Operations Runbook](docs/OPS_RUNBOOK.md) - Setup, troubleshooting, recovery
- [Performance Notes](docs/PERFORMANCE_NOTES.md) - Tuning recommendations

## ⚠️ Known Limitations

| Feature | Limitation | Workaround |
|---------|------------|------------|
| OPNsense | Not Docker-native | Alpine + Suricata substitute |
| FlexiWAN | Requires account | Self-hosted controller with free signup |
| Ziti+OIDC | Manual identity mapping | External JWT signer config |

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `make smoke-test`
5. Submit a pull request

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [FlexiWAN](https://flexiwan.com/) - Open source SD-WAN
- [OpenZiti](https://openziti.io/) - Zero Trust networking
- [Suricata](https://suricata.io/) - Network IDS/IPS
- [Wazuh](https://wazuh.com/) - Security platform
- [Keycloak](https://www.keycloak.org/) - Identity management

---

**Built with ❤️ for security practitioners and network engineers**
