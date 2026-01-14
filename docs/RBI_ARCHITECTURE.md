# Remote Browser Isolation Architecture

## Overview

OpenSASE Browser Isolation (OSBI) executes web browsing in secure containers at the PoP, streaming only safe pixels or sanitized DOM to end users.

```
User Device                     PoP Edge                        Internet
┌──────────┐    WebRTC/WSS    ┌────────────────────────────┐   ┌─────────┐
│ OSBI     │ ◄─────────────►  │ Container Orchestrator     │   │ Target  │
│ Client   │   Pixels/DOM     │ ┌────────────────────────┐ │   │ Website │
│          │                  │ │ Chromium Sandbox       │◄├──►│         │
│          │  ────────────►   │ │ (Isolated Container)   │ │   │         │
│          │  User Input      │ └────────────────────────┘ │   └─────────┘
└──────────┘                  │ ┌────────────────────────┐ │
                              │ │ Malware Scanner        │ │
                              │ │ DLP Engine             │ │
                              │ │ URL Policy             │ │
                              │ └────────────────────────┘ │
                              └────────────────────────────┘
```

---

## Isolation Modes

| Mode | Security | Performance | Bandwidth |
|------|----------|-------------|-----------|
| **Pixel-Push** | Maximum | Lower | Higher |
| **DOM Reconstruction** | High | Higher | Lower |
| **Hybrid** | High | Balanced | Medium |

### Pixel-Push (Default)
- H.264/VP9/AV1 encoded video stream
- No code execution on client
- Zero browser-based exploits possible
- 30fps @ 5Mbps typical

### DOM Reconstruction
- Sanitized DOM streamed to client
- Scripts/events stripped
- Client renders safe content
- Lower bandwidth, higher performance

---

## Container Security

```
┌─────────────────────────────────────────┐
│ Chromium Container                       │
├─────────────────────────────────────────┤
│ • seccomp profile (restricted syscalls) │
│ • no-new-privileges                     │
│ • CAP_DROP ALL (except SYS_ADMIN)       │
│ • 2GB memory limit                      │
│ • 2 CPU cores max                       │
│ • Ephemeral filesystem                  │
│ • No network to internal ranges         │
│ • DNS filtering enabled                 │
└─────────────────────────────────────────┘
```

---

## Security Layers

1. **URL Policy** - Block malware/phishing domains
2. **Container Isolation** - Chromium in locked-down container
3. **DLP Engine** - Detect sensitive data in clipboard/uploads
4. **Download Scanning** - ClamAV integration
5. **Session Recording** - Audit trail

---

## Modules

| Module | Lines | Purpose |
|--------|-------|---------|
| `lib.rs` | 450 | Core types, service |
| `container.rs` | 250 | Docker orchestration |
| `streaming.rs` | 350 | Pixel/DOM streaming |
| `policy.rs` | 300 | URL/DLP policies |
| `session.rs` | 180 | Session lifecycle |
| `input.rs` | 200 | Input validation |
| `download.rs` | 250 | Malware scanning |

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Session startup | <3s |
| Input latency | <50ms |
| Frame rate | 30fps |
| Concurrent sessions per PoP | 1,000+ |

---

## API

```rust
// Create session
let service = BrowserIsolationService::new(config);
let session = service.create_session("user-123", SessionConfig {
    initial_url: Some("https://example.com".to_string()),
    mode: IsolationMode::PixelPush,
    ..Default::default()
}).await?;

// Connect to stream
let rx = stream_manager.subscribe(&session.id);

// Handle input
service.handle_input(&session.id, InputEvent::Click { 
    x: 100.0, y: 200.0, button: MouseButton::Left 
}).await?;
```
