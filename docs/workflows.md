# Workflows -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Site Onboarding Workflow

```mermaid
sequenceDiagram
    participant Admin as Network Admin
    participant Portal as Portal (opensase-portal)
    participant API as API Gateway (api/src/)
    participant ORCH as Orchestrator
    participant EDGE as Edge Appliance (edge/src/)
    participant POP as PoP Security Stack

    Admin->>Portal: Create new site
    Portal->>API: POST /api/v1/tenants/:id/sites
    API->>ORCH: Provision site resources
    ORCH->>ORCH: Generate edge config + WireGuard keys
    ORCH-->>API: Site created with bootstrap token
    API-->>Portal: Site ID + ZTP token
    Admin->>EDGE: Power on edge appliance with ZTP token
    EDGE->>ORCH: Register with bootstrap token (ztp.rs)
    ORCH->>EDGE: Push configuration (tunnel endpoints, policies)
    EDGE->>EDGE: Configure interfaces (network.rs)
    EDGE->>POP: Establish WireGuard tunnel (tunnel.rs)
    POP-->>EDGE: Tunnel established
    EDGE->>EDGE: Start SD-WAN controller (sdwan.rs)
    EDGE->>EDGE: Initialize security stack (security.rs)
    EDGE-->>ORCH: Heartbeat: status=Running
    ORCH-->>Portal: Site status: Active
```

## 2. Policy Management Workflow

```mermaid
sequenceDiagram
    participant Admin as Security Admin
    participant Portal as Portal (Policies.tsx)
    participant API as API Gateway
    participant UPO as Unified Policy Orchestrator
    participant NATS as NATS JetStream
    participant EDGE as Edge Appliances

    Admin->>Portal: Create access policy
    Portal->>API: POST /api/v1/tenants/:id/policies
    API->>API: Validate policy (models.rs: PolicyCreate)
    API->>UPO: Compile intent policy (compiler.py)
    UPO->>UPO: Validate against schema
    UPO->>UPO: Compile to FlexiWAN + Suricata + Ziti configs
    UPO-->>API: CompiledOutput for each adapter
    API->>NATS: Publish "policy.updated" event
    NATS->>EDGE: Distribute to all affected edge devices
    EDGE->>EDGE: Apply local policy rules
    EDGE-->>API: Acknowledge policy applied
    API-->>Portal: Policy active, applied to N sites
```

## 3. Threat Detection and Response Workflow

```mermaid
sequenceDiagram
    participant FLOW as Network Flow
    participant VPP as VPP Data Plane
    participant ML as ML Threat Engine (ml/inference)
    participant ALERT as Alert Manager
    participant WAZUH as Wazuh SIEM
    participant PORTAL as Portal (Security.tsx)
    participant ANALYST as Security Analyst

    FLOW->>VPP: Packet arrives at PoP
    VPP->>VPP: Extract flow features
    VPP->>ML: Analyze flow (analyze_flow)
    ML->>ML: DNS detection (RF+CNN)
    ML->>ML: Network anomaly (IF+AE)
    ML->>ML: Behavioral analysis (LSTM)
    alt Threat detected (anomaly_score > 0.8)
        ML->>ALERT: Create ThreatAlert (alerts.rs)
        ALERT->>ALERT: Deduplicate, correlate, enrich
        ALERT->>ALERT: Map to MITRE ATT&CK technique
        ALERT->>WAZUH: Forward alert via syslog
        ALERT->>PORTAL: Push via WebSocket (ws.rs)
        PORTAL->>ANALYST: Display real-time alert
        ANALYST->>PORTAL: Investigate alert
        ANALYST->>PORTAL: Create block rule
    else Normal traffic
        VPP->>VPP: Forward packet
    end
```

## 4. VPN Client Connection Workflow

```mermaid
sequenceDiagram
    participant USER as End User
    participant CLIENT as Desktop Client (client/core)
    participant KC as Keycloak (OIDC)
    participant ZITI as OpenZiti Controller
    participant ROUTER as Ziti Router (PoP)
    participant APP as Private Application

    USER->>CLIENT: Launch OpenSASE client
    CLIENT->>KC: OIDC authentication flow
    KC-->>CLIENT: JWT token + identity
    CLIENT->>CLIENT: Posture check (posture.rs)
    CLIENT->>ZITI: Present identity + posture
    ZITI->>ZITI: Evaluate policy (identity + posture + time)
    alt Authorized
        ZITI-->>CLIENT: Session token + service list
        CLIENT->>CLIENT: Configure tunnel (tunnel.rs)
        USER->>CLIENT: Access app1.internal
        CLIENT->>ROUTER: mTLS connection
        ROUTER->>APP: Forward to private app
        APP-->>USER: Response (end-to-end encrypted)
    else Denied
        ZITI-->>CLIENT: Access denied (reason)
        CLIENT->>USER: Display error with remediation steps
    end
```

## 5. QoE Path Selection Workflow

```mermaid
sequenceDiagram
    participant PROBE as QoE Probes (probes.py)
    participant SCORER as Path Scorer (scorer.py)
    participant REC as Recommender (recommender.py)
    participant SDWAN as SD-WAN Controller (sdwan.rs)
    participant EDGE as Edge Appliance

    loop Every 5 seconds
        PROBE->>PROBE: Send ICMP/HTTP probes to all WAN links
        PROBE->>SCORER: ProbeResult (latency, jitter, loss)
        SCORER->>SCORER: Score each path per AppClass
        SCORER->>SCORER: Check SLA thresholds (voice: <30ms, <1% loss)
        SCORER->>REC: PathScore per WAN link per AppClass
        REC->>REC: Generate SteeringRecommendation
        alt Path change needed
            REC->>SDWAN: Update routing policy
            SDWAN->>EDGE: Apply new traffic steering rules
        end
    end
```

## 6. CASB SaaS Monitoring Workflow

```mermaid
sequenceDiagram
    participant CASB as CASB-Lite (casb_lite)
    participant G_API as Google Workspace API
    participant M_API as Microsoft 365 API
    participant NORM as Normalizer
    participant WAZUH as Wazuh SIEM
    participant PORTAL as Portal

    loop Every 60 minutes
        CASB->>G_API: Fetch audit logs
        CASB->>M_API: Fetch audit logs
        G_API-->>CASB: Raw events
        M_API-->>CASB: Raw events
        CASB->>NORM: Normalize to common schema (NormalizedEvent)
        NORM->>NORM: Classify risk level
        alt Risky sign-in detected
            NORM->>WAZUH: Export high-risk events
            NORM->>PORTAL: Push alert
        end
        NORM->>NORM: Update SaaS app inventory (SaaSApp)
        NORM->>NORM: Check OAuth permissions
    end
```

## 7. DLP Content Scanning Workflow

```mermaid
sequenceDiagram
    participant USER as User Upload
    participant SWG as Secure Web Gateway
    participant DLP as DLP Scanner (scanner.py)
    participant CLASS as Classifiers (regex, ML)
    participant ALERT as Alert System

    USER->>SWG: Upload file to cloud service
    SWG->>DLP: ScanRequest (content, filename, source)
    DLP->>CLASS: Run all enabled classifiers
    CLASS->>CLASS: SSN detection (regex)
    CLASS->>CLASS: Credit card detection (Luhn + regex)
    CLASS->>CLASS: API key detection (pattern matching)
    CLASS-->>DLP: List of ClassifierMatch results
    DLP->>DLP: Deduplicate overlapping matches
    DLP->>DLP: Determine highest severity
    alt Sensitive data found
        DLP-->>SWG: ScanResult (has_sensitive_data=true)
        SWG->>SWG: Block upload per policy
        SWG->>ALERT: DLP violation alert
    else No sensitive data
        DLP-->>SWG: ScanResult (has_sensitive_data=false)
        SWG->>SWG: Allow upload
    end
```

## 8. Edge High Availability Failover Workflow

```mermaid
stateDiagram-v2
    [*] --> ActiveStandby: HA pair initialized
    ActiveStandby --> ActiveActive: Both healthy

    state ActiveStandby {
        [*] --> Primary_Active
        Primary_Active --> Primary_Failed: Health check fails
        Primary_Failed --> Standby_Promoted: Failover (< 3 sec)
        Standby_Promoted --> Primary_Active: Original primary recovers
    }
```

## 9. Smoke Test Workflow

From `scripts/smoke-test.sh`, automated validation runs these tests:

| Test | Description | Pass Criteria |
|------|-------------|---------------|
| T1 | SD-WAN overlay ping | Branch A/B/C ping each other via overlay |
| T2 | ZTNA access to App1 | Access nginx via Ziti (no public port) |
| T3 | ZTNA access to App2 | Access httpbin via Ziti (no public port) |
| T4 | Suricata IPS mode | IPS running in inline mode |
| T5 | IPS logging | eve.json receiving events |
| T6 | Wazuh agent registration | All agents connected to manager |
| T7 | Wazuh alert generation | Synthetic alerts indexed |
| T8 | Keycloak health | OIDC endpoints responding |
| T9 | Portal API health | /api/health returns healthy |

## 10. Incident Response Workflow

```mermaid
flowchart TB
    A["Threat Detected<br/>(ML Engine or Suricata)"] --> B{"Severity?"}
    B -->|Critical| C["Auto-Block Source IP<br/>via XDP/sase-ddos"]
    B -->|High| D["Alert SOC + Log"]
    B -->|Medium| E["Enrich + Log"]
    B -->|Low| F["Log Only"]
    C --> G["Create Incident in Wazuh"]
    D --> G
    G --> H["Analyst Investigates<br/>via Portal Security page"]
    H --> I["Remediate"]
    I --> J["Update Policies"]
    J --> K["Post-Incident Review"]
    K --> L["Close Incident"]
```
