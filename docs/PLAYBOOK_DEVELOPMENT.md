# SOAR Playbook Development Guide

## Playbook Anatomy

```yaml
playbook:
  id: unique-id
  name: "Human Readable Name"
  description: "What this playbook does"
  version: 1
  enabled: true
  
  trigger:
    type: alert_type | severity | threat_intel | manual | scheduled
    value: "trigger condition"
    
  steps:
    - id: step1
      name: "Step Description"
      action: action_type
      params:
        key: value
      condition: "optional condition"
      timeout: 30s
      retries: 3
      on_success: next_step_id
      on_failure: error_step_id
```

---

## Triggers

### Alert Type Trigger

```yaml
trigger:
  type: alert_type
  value: "MalwareDetected"
```

### Severity Trigger

```yaml
trigger:
  type: severity
  min: High  # Info, Low, Medium, High, Critical
```

### Threat Intel Match

```yaml
trigger:
  type: threat_intel
  sources:
    - AlienVault
    - AbuseIPDB
```

### MITRE ATT&CK

```yaml
trigger:
  type: mitre
  techniques:
    - T1110  # Brute Force
    - T1046  # Port Scan
```

### Scheduled

```yaml
trigger:
  type: scheduled
  cron: "0 */6 * * *"  # Every 6 hours
```

---

## Available Actions

### Enrichment Actions

#### enrich_indicator
Look up indicators in threat intel

```yaml
- id: enrich
  action: enrich_indicator
  params:
    types:
      - ip
      - domain
      - hash
    sources:
      - virustotal
      - otx
```

#### lookup_asset
Get asset details from CMDB

```yaml
- id: asset_lookup
  action: lookup_asset
  params:
    field: source_ip
```

### Response Actions

#### block_ip
Block IP at firewall/WAF

```yaml
- id: block
  action: block_ip
  params:
    ip_field: source_ip
    duration: 3600  # seconds, 0 = permanent
    firewall: palo_alto
```

#### isolate_device
Network isolate endpoint via EDR

```yaml
- id: isolate
  action: isolate_device
  params:
    device_field: source_host
    edr: crowdstrike  # crowdstrike, defender, sentinelone
```

#### disable_user
Disable user account

```yaml
- id: disable
  action: disable_user
  params:
    user_field: username
    idp: okta  # okta, azure_ad, google
```

### Notification Actions

#### send_slack

```yaml
- id: notify
  action: send_slack
  params:
    channel: "#security-alerts"
    message: "Alert: ${alert.summary}"
```

#### send_email

```yaml
- id: email
  action: send_email
  params:
    to: "soc@example.com"
    subject: "Security Alert: ${alert.type}"
    template: incident_notification
```

#### page_oncall

```yaml
- id: page
  action: page_oncall
  params:
    team: security-team
    severity: critical
```

### Case Management

#### create_case

```yaml
- id: case
  action: create_case
  params:
    template: malware-incident
    priority: P2
    assign_to: auto
```

#### create_ticket

```yaml
- id: ticket
  action: create_ticket
  params:
    system: jira
    project: SEC
    type: Incident
```

---

## Conditions

Use conditions to control step execution:

```yaml
- id: isolate
  action: isolate_device
  condition: "alert.severity >= 'High' AND asset.criticality == 'critical'"
```

### Available Fields

| Field | Description |
|-------|-------------|
| `alert.severity` | Alert severity |
| `alert.type` | Alert type |
| `event.source_ip` | Source IP |
| `event.user` | Username |
| `asset.criticality` | Asset criticality |
| `threat_intel.matched` | TI match found |
| `step.{id}.output` | Previous step output |

### Operators

| Operator | Example |
|----------|---------|
| `==` | `severity == 'High'` |
| `!=` | `status != 'closed'` |
| `>=`, `<=` | `severity >= 'Medium'` |
| `AND`, `OR` | `a AND b` |
| `IN` | `type IN ['malware', 'ransomware']` |
| `CONTAINS` | `tags CONTAINS 'apt'` |

---

## Example Playbooks

### Brute Force Response

```yaml
playbook:
  id: brute-force-response
  name: "Brute Force Response"
  
  trigger:
    type: alert_type
    value: "BruteForceAttempt"
    
  steps:
    - id: enrich
      action: enrich_indicator
      params:
        types: [ip]
      on_success: block
      
    - id: block
      action: block_ip
      params:
        ip_field: source_ip
        duration: 86400  # 24 hours
      on_success: notify
      
    - id: notify
      action: send_slack
      params:
        channel: "#security-alerts"
        message: "Blocked brute force source: ${event.source_ip}"
```

### Data Exfiltration

```yaml
playbook:
  id: data-exfil-response
  name: "Data Exfiltration Response"
  
  trigger:
    type: alert_type
    value: "DataExfiltration"
    
  steps:
    - id: isolate
      action: isolate_device
      params:
        device_field: source_host
      on_success: disable_user
      
    - id: disable_user
      action: disable_user
      params:
        user_field: username
      on_success: create_case
      
    - id: create_case
      action: create_case
      params:
        template: data-breach
        priority: P1
      on_success: page
      
    - id: page
      action: page_oncall
      params:
        team: incident-response
        severity: critical
```

### Threat Intel Alert

```yaml
playbook:
  id: ti-match-response
  name: "Threat Intel Match"
  
  trigger:
    type: threat_intel
    sources: [any]
    
  steps:
    - id: enrich
      action: enrich_indicator
      params:
        deep_scan: true
      on_success: evaluate
      
    - id: evaluate
      action: evaluate_risk
      on_success: respond
      
    - id: respond
      action: conditional
      branches:
        - condition: "risk_score >= 80"
          goto: isolate
        - condition: "risk_score >= 50"
          goto: alert
        - default: log
          
    - id: isolate
      action: isolate_device
      on_success: case
      
    - id: alert
      action: send_slack
      params:
        channel: "#security-alerts"
        
    - id: case
      action: create_case
      params:
        template: ti-investigation
```

---

## Testing Playbooks

### Dry Run

```bash
opensase-cli playbook test \
  --playbook-id malware-response \
  --dry-run \
  --event-file test_event.json
```

### Debug Mode

```yaml
playbook:
  debug: true  # Enable detailed logging
```

---

## Best Practices

1. **Start simple** - Begin with basic playbooks, add complexity gradually
2. **Test thoroughly** - Use dry-run before production
3. **Handle failures** - Always define on_failure paths
4. **Limit scope** - One playbook per threat type
5. **Document** - Add descriptions to all steps
6. **Review regularly** - Update based on learnings
