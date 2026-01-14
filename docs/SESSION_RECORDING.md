# OpenSASE Session Recording

## Overview

Session recording captures all privileged access activity for compliance and forensics.

---

## Recording Types

| Type | Use Case | Data Captured |
|------|----------|---------------|
| **Full** | High-risk sessions | Screen, keystrokes, network, files |
| **ScreenOnly** | Visual audit | Screen frames |
| **KeystrokeOnly** | Command audit | All keystrokes |
| **Commands** | CLI sessions | Command execution |
| **Network** | Data transfer | Network packets |

---

## When Recording Triggers

| Condition | Recording Type |
|-----------|----------------|
| Trust Score 40-59 | Full |
| Sensitive Resource | Full |
| Admin Access | Full |
| SSH Session | Commands |
| RDP Session | Screen |
| File Download | Network |

---

## Recorded Activities

### Keystrokes
```rust
KeystrokeData {
    timestamp: DateTime,
    key_code: u32,
    modifiers: u8,
    application: String,
}
```

### Screen Frames
```rust
ScreenFrameData {
    timestamp: DateTime,
    width: u32,
    height: u32,
    frame_type: KeyFrame | Delta,
    data: Vec<u8>,
}
```

### Commands
```rust
CommandData {
    timestamp: DateTime,
    command: String,
    working_dir: String,
    exit_code: Option<i32>,
}
```

### File Access
```rust
FileAccessData {
    timestamp: DateTime,
    operation: Read | Write | Upload | Download,
    path: String,
    size_bytes: u64,
}
```

---

## Replay Capabilities

| Feature | Description |
|---------|-------------|
| **Playback** | Video-like replay of session |
| **Search** | Find specific commands/files |
| **Timeline** | Navigate to any point |
| **Export** | Download for audit |

---

## Retention Policy

| Classification | Retention |
|----------------|-----------|
| Admin sessions | 2 years |
| Privileged access | 1 year |
| Standard access | 90 days |
| Security incidents | 7 years |

---

## Compliance Standards

- SOC 2 Type II
- HIPAA
- PCI-DSS
- GDPR (with consent)
- ISO 27001

---

## Privacy Controls

| Control | Description |
|---------|-------------|
| **Redaction** | Mask sensitive data in recordings |
| **Encryption** | AES-256 at rest |
| **Access Control** | RBAC for replay access |
| **Audit Log** | Track who views recordings |
