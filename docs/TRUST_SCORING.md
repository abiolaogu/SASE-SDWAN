# OpenSASE Zero Trust Access (OZTA) - Trust Scoring

## Trust Score Calculation

The trust score is a composite of four weighted factors:

```
Trust Score = (Identity × 30%) + (Device × 30%) + (Context × 20%) + (Behavior × 20%)
```

---

## Identity Score (30% weight)

| Factor | Impact |
|--------|--------|
| **Password Only** | -20 |
| **Password + MFA** | +15 |
| **FIDO2/WebAuthn** | +30 |
| **Biometric** | +25 |
| **Certificate** | +25 |
| **Stale Auth (>8hr)** | -10 |
| **Untrusted IdP** | -15 |

---

## Device Score (30% weight)

| Factor | Impact |
|--------|--------|
| **Fully Managed** | +25 |
| **Partially Managed** | +10 |
| **Unmanaged** | -20 |
| **No Antivirus** | -15 |
| **Firewall Disabled** | -10 |
| **Disk Not Encrypted** | -15 |
| **OS Patches >30 days** | -20 |
| **Jailbroken/Rooted** | -40 |
| **No Screen Lock** | -10 |

---

## Context Score (20% weight)

| Factor | Impact |
|--------|--------|
| **Corporate Network** | +15 |
| **Home Network** | 0 |
| **Public WiFi** | -15 |
| **Cellular** | -5 |
| **VPN/Proxy** | -10 |
| **Tor Exit** | -40 |
| **Unusual Hours** | -10 |
| **Impossible Travel** | -30 |
| **Restricted Country** | -50 |

---

## Behavior Score (20% weight)

| Factor | Impact |
|--------|--------|
| **Known Device** | 0 |
| **New Device** | -10 |
| **Known Location** | 0 |
| **New Location** | -15 |
| **Normal Pattern** | 0 |
| **Anomalous Access** | -20 |

---

## Risk Signal Penalties

| Signal | Penalty |
|--------|---------|
| Low Severity | -5 |
| Medium Severity | -15 |
| High Severity | -30 |
| Critical Severity | -50 |

---

## Access Decisions

| Score Range | Decision | Actions |
|-------------|----------|---------|
| **80-100** | Allow | Full access |
| **60-79** | Allow + MFA | Step-up authentication required |
| **40-59** | Allow + Record | Session recording enabled |
| **0-39** | Deny | Block access |

---

## Continuous Evaluation

- Re-evaluated every **60 seconds**
- Trust degradation >20 points triggers step-up
- Critical signals cause immediate session suspension

---

## Example Calculations

### High Trust User (Corporate Device)
```
Identity: Password + MFA = 50 + 15 = 65
Device:   Managed + AV + FW + Encrypted = 50 + 25 + 10 + 15 = 100 (capped)
Context:  Corporate Network = 70 + 15 = 85
Behavior: Known device, known location = 80

Trust = (65 × 0.30) + (100 × 0.30) + (85 × 0.20) + (80 × 0.20)
     = 19.5 + 30.0 + 17.0 + 16.0 = 82.5 → ALLOW
```

### Medium Trust User (BYOD)
```
Identity: Password only = 50 - 20 = 30
Device:   Unmanaged = 50 - 20 = 30
Context:  Home network = 70
Behavior: Known device = 80

Trust = (30 × 0.30) + (30 × 0.30) + (70 × 0.20) + (80 × 0.20)
     = 9.0 + 9.0 + 14.0 + 16.0 = 48.0 → ALLOW + RECORD
```

### Low Trust User (Public WiFi + New Device)
```
Identity: Password only = 30
Device:   Unmanaged + No AV = 30 - 15 = 15
Context:  Public WiFi = 70 - 15 = 55
Behavior: New device = 80 - 10 = 70

Trust = (30 × 0.30) + (15 × 0.30) + (55 × 0.20) + (70 × 0.20)
     = 9.0 + 4.5 + 11.0 + 14.0 = 38.5 → DENY
```
