# RBI Security Model

## Overview

OpenSASE Browser Isolation (OSBI) provides complete protection against browser-based threats by executing all web content in isolated containers at the PoP.

---

## Security Layers

```
User Device                 PoP Edge                     Internet
┌──────────────┐          ┌────────────────────────┐    ┌──────────┐
│ Safe Pixels  │◄─────────│ Isolation Container    │    │ Untrusted│
│ Only         │  WebRTC  │ ┌────────────────────┐ │    │ Website  │
│              │          │ │ Chromium + seccomp │◄├───►│          │
│ No Code      │          │ │ No network to LAN  │ │    │          │
│ Execution    │          │ └────────────────────┘ │    └──────────┘
└──────────────┘          │ ┌────────────────────┐ │
                          │ │ CDR File Sanitizer │ │
                          │ └────────────────────┘ │
                          └────────────────────────┘
```

---

## Container Isolation

### Security Controls
| Control | Value | Purpose |
|---------|-------|---------|
| `runAsNonRoot` | true | Prevent root execution |
| `readOnlyRootFilesystem` | true | Immutable container |
| `allowPrivilegeEscalation` | false | No privilege gain |
| `capabilities.drop` | ALL | Minimal capabilities |
| `seccompProfile` | RuntimeDefault | Syscall filtering |
| `AppArmor` | runtime/default | MAC enforcement |

### Network Isolation
- **No host network access**
- **Egress only via filtered proxy**
- **Blocked CIDRs**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **DNS filtering enabled**

---

## Chrome Policies (Hardened)

```json
{
  "ExtensionInstallBlocklist": ["*"],
  "DownloadRestrictions": 3,
  "DeveloperToolsAvailability": 2,
  "PrintingEnabled": false,
  "AudioCaptureAllowed": false,
  "VideoCaptureAllowed": false,
  "ScreenCaptureAllowed": false,
  "PasswordManagerEnabled": false,
  "AutofillCreditCardEnabled": false
}
```

---

## Content Disarm & Reconstruct (CDR)

All downloads are sanitized before reaching the user.

| File Type | Sanitization | Threats Removed |
|-----------|--------------|-----------------|
| **PDF** | Flatten to images | JavaScript, embedded files, forms |
| **Office** | Convert to PDF | VBA macros, external links, OLE objects |
| **Images** | Re-encode | EXIF, steganography, polyglots |
| **Archives** | Recursive scan | Nested threats, path traversal |
| **Executables** | **BLOCKED** | - |
| **Scripts** | **BLOCKED** | - |

---

## Input Sanitization

| Control | Purpose |
|---------|---------|
| Rate limiting | Prevent input flooding |
| Key combo filtering | Block F12, Ctrl+Shift+I |
| Paste size limits | Max 100KB |
| Coordinate validation | Bounds checking |

---

## Clipboard Isolation

- **Copy**: Content sanitized before reaching user
- **Paste**: Validated and size-limited
- **DLP integration**: Sensitive data detection

---

## Session Security

- **Ephemeral containers**: Destroyed after session
- **Memory-backed filesystem**: No persistent storage
- **Session timeout**: 1 hour default
- **Per-user session limits**: Max 5 concurrent

---

## Threat Model

### Protected Against
✅ Drive-by downloads  
✅ Browser exploits  
✅ Zero-day vulnerabilities  
✅ Malicious JavaScript  
✅ Credential harvesting (blocked autofill)  
✅ Cryptomining  
✅ Malware downloads (CDR)  

### Not Protected Against
❌ User intentionally downloading malware (after CDR warning)
❌ Phishing via visual deception (requires user training)
❌ Denial of service to RBI infrastructure

---

## Audit & Compliance

- Session recording (optional)
- URL access logging
- File transfer logging
- DLP violation alerts
