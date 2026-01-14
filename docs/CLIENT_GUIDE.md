# OpenSASE Client Suite

## Overview

Cross-platform SASE client providing secure connectivity, device posture assessment, and ZTNA integration.

## Supported Platforms

| Platform | Architecture | Status |
|----------|--------------|--------|
| Windows 10/11 | x64, ARM64 | ✅ |
| macOS 12+ | Intel, Apple Silicon | ✅ |
| Linux | x64, ARM64 | ✅ |
| iOS 15+ | ARM64 | ✅ |
| Android 10+ | ARM64, ARM32 | ✅ |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      OpenSASE Client                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Tunnel    │  │   Posture   │  │   Policy    │             │
│  │  Manager    │  │  Collector  │  │   Engine    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │    Auth     │  │    DNS      │  │ Connection  │             │
│  │  Manager    │  │  Manager    │  │  Manager    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Platform Abstraction Layer                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │              │              │              │          │
│    ┌────┴───┐    ┌────┴───┐    ┌────┴───┐    ┌────┴───┐      │
│    │Windows │    │ macOS  │    │ Linux  │    │ Mobile │      │
│    └────────┘    └────────┘    └────────┘    └────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `lib.rs` | Main client and core types |
| `tunnel.rs` | WireGuard tunnel management |
| `posture.rs` | Device posture collection |
| `policy.rs` | Split tunnel and app policies |
| `auth.rs` | Authentication and tokens |
| `dns.rs` | DNS protection |
| `connection.rs` | Auto-reconnect logic |
| `platform.rs` | Platform abstraction |
| `config.rs` | Configuration persistence |
| `ffi.rs` | C bindings for mobile/desktop |

## Features

### Secure Tunneling
- WireGuard-based VPN
- Always-on protection
- Kill switch support
- Automatic reconnection

### Device Posture
- OS version and updates
- Firewall status
- Antivirus/EDR detection
- Disk encryption (BitLocker, FileVault)
- Jailbreak/root detection

### Policy Enforcement
- Split tunneling
- Application blocking
- DNS protection
- Network access control

### Battery Efficiency
- Efficient WireGuard protocol
- Smart keepalive intervals
- Background optimization

## Building

### Desktop (Windows/macOS/Linux)

```bash
# Build for current platform
cargo build --release -p sase-client

# Cross-compile for Windows
cargo build --release -p sase-client --target x86_64-pc-windows-gnu

# Cross-compile for macOS
cargo build --release -p sase-client --target aarch64-apple-darwin
```

### Mobile (iOS/Android)

```bash
# iOS (requires Xcode)
cargo build --release -p sase-client --target aarch64-apple-ios

# Android
cargo ndk -t arm64-v8a build --release -p sase-client
```

### Generate C Headers

```bash
cbindgen --config cbindgen.toml --crate sase-client --output opensase.h
```

## FFI Usage

### Swift (iOS/macOS)

```swift
import OpenSASE

let client = oscs_init("https://sase.example.com", "tenant-123")
defer { oscs_free(client) }

oscs_connect(client) { success, error in
    if success {
        print("Connected!")
    } else {
        print("Error: \(String(cString: error!))")
    }
}
```

### Kotlin (Android)

```kotlin
import com.opensase.client.OpenSASE

val client = OpenSASE.init("https://sase.example.com", "tenant-123")

client.connect { success, error ->
    if (success) {
        Log.d("OpenSASE", "Connected!")
    } else {
        Log.e("OpenSASE", "Error: $error")
    }
}
```

### C# (Windows)

```csharp
using OpenSASE;

var client = NativeMethods.oscs_init(serverUrl, tenantId);

NativeMethods.oscs_connect(client, (success, error) => {
    if (success) {
        Console.WriteLine("Connected!");
    }
});
```

## Configuration

### Config File Location

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\OpenSASE\config.json` |
| macOS | `~/Library/Application Support/OpenSASE/config.json` |
| Linux | `~/.config/opensase/config.json` |

### Example Config

```json
{
  "server": {
    "url": "https://sase.example.com",
    "tenant_id": "your-tenant-id"
  },
  "connection": {
    "auto_connect": true,
    "auto_reconnect": true,
    "reconnect_delay_ms": 1000,
    "keepalive_interval_secs": 25
  },
  "features": {
    "always_on": true,
    "split_tunnel": true,
    "dns_protection": true,
    "posture_check": true,
    "kill_switch": false
  }
}
```

## Posture Scoring

| Check | Points | Weight |
|-------|--------|--------|
| OS Up-to-date | 10 | High |
| Auto-update enabled | 10 | Medium |
| Firewall enabled | 10 | High |
| Antivirus installed | 10 | High |
| Antivirus up-to-date | 5 | Medium |
| EDR installed | 10 | High |
| Screen lock enabled | 5 | Medium |
| Disk encryption | 15 | Critical |
| Not jailbroken | 5 | Critical |

**Compliance threshold**: 70 points

## Integration with ZTNA

The client integrates with the OpenSASE ZTNA gateway:

1. **Device Authentication**: Device certificate or enrolled device ID
2. **Posture Submission**: Posture data sent with each auth request
3. **Trust Evaluation**: Server calculates trust score
4. **Policy Retrieval**: Client receives split tunnel and access policies
5. **Tunnel Establishment**: WireGuard tunnel to nearest PoP
6. **Continuous Monitoring**: Periodic posture re-evaluation
