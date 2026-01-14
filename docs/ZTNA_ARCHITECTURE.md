# OpenSASE Zero Trust Access (OZTA)

## Access Request Flow

```
User Device ──→ [OpenSASE Client/Browser]
│
▼
┌─────────────────────────────────────────────────────────────┐
│                    TRUST EVALUATION ENGINE                   │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   Identity  │  │   Device    │  │   Context   │          │
│  │   Verify    │  │   Posture   │  │   Analysis  │          │
│  │   (IdP)     │  │   Check     │  │   (Risk)    │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
│         │                │                │                  │
│         └────────────────┼────────────────┘                  │
│                          │                                   │
│                          ▼                                   │
│               ┌─────────────────────┐                       │
│               │   TRUST SCORE       │                       │
│               │   0-100             │                       │
│               └─────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│                    POLICY DECISION POINT                     │
│                                                               │
│  Trust Score + Requested Resource → Access Decision          │
│                                                               │
│  [ALLOW] [ALLOW + MFA] [ALLOW + SESSION RECORD] [DENY]      │
└─────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION CONNECTOR                     │
│                                                               │
│  • Micro-tunnel to application                               │
│  • Session binding                                           │
│  • Activity logging                                          │
│  • Data loss prevention                                      │
└─────────────────────────────────────────────────────────────┘
│
▼
Protected Application
```

---

### Identity & Authentication
| Module | Purpose |
|--------|---------|
| identity.rs | IdP verification, device registry |
| authn.rs | Credential authentication |
| mfa.rs | TOTP, WebAuthn, Push, SMS |
| sso.rs | SAML, OIDC integration |
| device.rs | Device posture, trust scoring |

### Authorization
| Module | Purpose |
|--------|---------|
| authz.rs | Fine-grained authorization |
| policy.rs | ABAC/RBAC policy engine |

### Risk & Continuous
| Module | Purpose |
|--------|---------|
| context.rs | Access context, risk signals |
| risk.rs | Real-time risk scoring |
| continuous.rs | Session re-evaluation |

### Network & Session
| Module | Purpose |
|--------|---------|
| microseg.rs | Network segmentation |
| session.rs | Session lifecycle |
| audit.rs | Audit trail |

---

## Risk Signals

| Signal | Severity | Weight |
|--------|----------|--------|
| Impossible Travel | High | 40 |
| Compromised Credential | Critical | 80 |
| Malware Detected | Critical | 90 |
| Privilege Escalation | High | 60 |
| New Device | Medium | 15 |
| New Location | Medium | 10 |
| Unusual Time | Low | 5 |

---

## Device Trust Levels

| Level | Score | Access |
|-------|-------|--------|
| Full | 80+ | All resources |
| High | 60-79 | Standard access |
| Medium | 40-59 | Limited access |
| Low | 20-39 | Basic only |
| Untrusted | <20 | Blocked |

---

## Policy Conditions

```rust
PolicyCondition::And(vec![
    PolicyCondition::MinTrustLevel(TrustLevel::High),
    PolicyCondition::MfaVerified,
    PolicyCondition::FromNetwork(NetworkType::Corporate),
    PolicyCondition::DuringHours { start: 8, end: 18 },
])
```

---

## Micro-Segmentation

```
Internet (Untrusted)
       │
       ▼ [DENY ALL]
   ┌───────────┐
   │    DMZ    │
   └─────┬─────┘
         │ [Limited]
   ┌─────▼─────┐
   │  Internal │
   └─────┬─────┘
         │ [MFA Required]
   ┌─────▼─────┐
   │ Sensitive │
   └───────────┘
```

---

## Integration

```rust
let gateway = ZeroTrustGateway::new(ZtnaConfig::default());

let request = AccessRequest {
    id: Uuid::new_v4().to_string(),
    identity,
    device,
    resource,
    action: AccessAction::Read,
    context,
    timestamp: Utc::now(),
};

let decision = gateway.request_access(request).await;

match decision.decision {
    Decision::Allow => { /* Grant access */ }
    Decision::Deny => { /* Block with reason */ }
    Decision::Challenge => { /* Require MFA */ }
    Decision::StepUp => { /* Require additional auth */ }
}
```
