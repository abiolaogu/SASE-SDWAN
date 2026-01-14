# Device Posture Collection Guide

## Overview

OpenSASE clients collect comprehensive device security posture to enable Zero Trust access decisions. Posture data is collected locally, scored, and transmitted to gateways during authentication.

## Collection Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Posture Collector                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Platform Collectors                 │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│  │  │ Windows │ │  macOS  │ │  Linux  │ │ Mobile  │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Posture Result                     │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│  │  │   OS    │ │Security │ │  Disk   │ │ Network │   │   │
│  │  │ Posture │ │ Posture │ │ Posture │ │ Posture │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│                    ┌──────┴──────┐                          │
│                    │   Score     │                          │
│                    │ Calculator  │                          │
│                    └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

## Platform-Specific Checks

### Windows

| Check | Method | API/Tool |
|-------|--------|----------|
| BitLocker | WMI | `Win32_EncryptableVolume` |
| Windows Defender | WMI | `AntiVirusProduct` |
| Windows Firewall | COM | `INetFwMgr` |
| EDR Installed | Service check | `CSFalconService`, `Sense` |
| Windows Update | COM | `IUpdateSession` |
| TPM Attestation | Windows API | `TpmVirtualSmartCard` |
| Screen Lock | Registry | `ScreenSaveActive` |
| Secure Boot | Registry | UEFI variables |

```rust
#[cfg(target_os = "windows")]
impl WindowsPostureCollector {
    pub async fn check_bitlocker(&self) -> Result<bool> {
        // Query WMI for BitLocker status
        let wmi = WmiConnection::new()?;
        let volumes: Vec<BitLockerVolume> = wmi.query(
            "SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'"
        )?;
        Ok(volumes.iter().any(|v| v.protection_status == 1))
    }
    
    pub async fn check_windows_defender(&self) -> Result<bool> {
        let wmi = WmiConnection::new()?;
        let products: Vec<AntiVirusProduct> = wmi.query(
            "SELECT * FROM AntiVirusProduct"
        )?;
        Ok(products.iter().any(|av| av.product_state.is_enabled()))
    }
    
    pub async fn check_edr(&self) -> Result<bool> {
        let known_edr = ["CSFalconService", "Sense", "CylanceSvc", "SentinelAgent"];
        for service in known_edr {
            if self.is_service_running(service).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
```

### macOS

| Check | Method | API/Tool |
|-------|--------|----------|
| FileVault | CLI | `fdesetup status` |
| Firewall | defaults | `com.apple.alf` |
| XProtect | File check | Bundle exists |
| Gatekeeper | CLI | `spctl --status` |
| SIP | CLI | `csrutil status` |
| Secure Enclave | Security.framework | Key attestation |
| Screen Lock | CLI | `defaults read` |

```swift
// macOS Posture Collection
class MacOSPostureCollector {
    func checkFileVault() async -> Bool {
        let output = try? Process.execute("fdesetup", arguments: ["status"])
        return output?.contains("FileVault is On") ?? false
    }
    
    func checkFirewall() async -> Bool {
        let output = try? Process.execute("defaults", arguments: [
            "read", "/Library/Preferences/com.apple.alf", "globalstate"
        ])
        return (Int(output?.trimmingCharacters(in: .whitespaces) ?? "0") ?? 0) > 0
    }
    
    func checkSIP() async -> Bool {
        let output = try? Process.execute("csrutil", arguments: ["status"])
        return output?.contains("enabled") ?? false
    }
    
    func getSecureEnclaveAttestation() async -> HardwareAttestation? {
        // Generate attestation using Secure Enclave
        let key = try? SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave
        ] as CFDictionary, nil)
        // Create attestation blob
        return HardwareAttestation(...)
    }
}
```

### Linux

| Check | Method | API/Tool |
|-------|--------|----------|
| LUKS | CLI | `lsblk -o TYPE` |
| iptables | CLI | `iptables -L` |
| nftables | CLI | `nft list ruleset` |
| ClamAV | systemd | Service status |
| SELinux | File | `/sys/fs/selinux/enforce` |
| AppArmor | File | `/sys/kernel/security/apparmor` |
| TPM | CLI | `tpm2_getcap` |

```rust
#[cfg(target_os = "linux")]
impl LinuxPostureCollector {
    pub async fn check_disk_encryption(&self) -> Result<bool> {
        let output = Command::new("lsblk")
            .args(["-o", "NAME,TYPE", "--json"])
            .output()
            .await?;
        
        let lsblk: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        
        // Check for crypt type devices
        if let Some(devices) = lsblk["blockdevices"].as_array() {
            for device in devices {
                if device["type"] == "crypt" {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    
    pub async fn check_firewall(&self) -> Result<bool> {
        // Check iptables
        let iptables = Command::new("iptables").args(["-L", "-n"]).output().await?;
        if iptables.status.success() {
            let stdout = String::from_utf8_lossy(&iptables.stdout);
            if stdout.lines().count() > 8 {
                return Ok(true);
            }
        }
        
        // Check nftables
        let nft = Command::new("nft").args(["list", "ruleset"]).output().await?;
        if nft.status.success() && !nft.stdout.is_empty() {
            return Ok(true);
        }
        
        Ok(false)
    }
}
```

### iOS

| Check | Method | API/Tool |
|-------|--------|----------|
| Passcode | Keychain | `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` |
| Jailbreak | File check | Known paths |
| MDM Enrolled | DCDeviceCondition | Device check |
| Secure Enclave | Security.framework | Key attestation |
| Screen Lock | LocalAuthentication | `canEvaluatePolicy` |

```swift
// iOS Posture Collection
class IOSPostureCollector {
    func checkPasscode() -> Bool {
        let context = LAContext()
        return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }
    
    func checkJailbreak() -> Bool {
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        // Check if can write to system
        let testPath = "/private/jailbreak_test"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
}
```

### Android

| Check | Method | API/Tool |
|-------|--------|----------|
| Root | File check | `/system/bin/su`, etc. |
| Screen Lock | KeyguardManager | `isDeviceSecure` |
| Encryption | DevicePolicyManager | `storageEncryptionStatus` |
| Developer Mode | Settings | `DEVELOPMENT_SETTINGS_ENABLED` |
| Unknown Sources | Settings/PackageManager | `canRequestPackageInstalls` |
| Play Protect | PlayCore | Status API |
| Key Attestation | AndroidKeyStore | `setAttestationChallenge` |

```kotlin
class AndroidPostureCollector(private val context: Context) {
    
    fun checkRoot(): Boolean {
        val paths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su"
        )
        
        for (path in paths) {
            if (File(path).exists()) return true
        }
        
        return try {
            Runtime.getRuntime().exec("su")
            true
        } catch (e: Exception) {
            false
        }
    }
    
    fun checkScreenLock(): Boolean {
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguard.isDeviceSecure
    }
    
    suspend fun getHardwareAttestation(): HardwareAttestation? {
        val keyGen = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        
        keyGen.initialize(
            KeyGenParameterSpec.Builder("attestation_key", KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build()
        )
        
        val keyPair = keyGen.generateKeyPair()
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val chain = keyStore.getCertificateChain("attestation_key")
        
        return HardwareAttestation(
            platform = "android",
            attestationType = "key_attestation",
            attestationData = Base64.encodeToString(...)
        )
    }
}
```

## Scoring Algorithm

```rust
pub fn calculate_score(posture: &DevicePosture) -> u32 {
    let mut score = 0u32;
    
    // Disk Encryption (20 points)
    if posture.disk_encrypted {
        score += 20;
    }
    
    // Firewall (10 points)
    if posture.firewall_enabled {
        score += 10;
    }
    
    // Antivirus (10 points)
    if posture.antivirus_active {
        score += 10;
    }
    
    // EDR (10 points)
    if posture.edr_installed {
        score += 10;
    }
    
    // OS Updates (15 points)
    if posture.os_patch_age_days < 30 {
        score += 15;
    } else if posture.os_patch_age_days < 60 {
        score += 10;
    } else if posture.os_patch_age_days < 90 {
        score += 5;
    }
    
    // Screen Lock (10 points)
    if posture.screen_lock_enabled {
        score += 5;
        if posture.screen_lock_timeout.unwrap_or(999) <= 5 {
            score += 5;
        }
    }
    
    // Device Integrity (15 points)
    if !posture.is_jailbroken && !posture.is_rooted {
        score += 15;
    }
    
    // Hardware Attestation (10 points)
    if posture.hardware_attestation.is_some() {
        score += 10;
    }
    
    score
}
```

## Scoring Breakdown

| Category | Max Points | Criteria |
|----------|------------|----------|
| Disk Encryption | 20 | BitLocker/FileVault/LUKS enabled |
| Firewall | 10 | System firewall enabled |
| Antivirus | 10 | AV product active |
| EDR | 10 | EDR solution installed |
| OS Updates | 15 | <30 days: 15, <60: 10, <90: 5 |
| Screen Lock | 10 | Enabled: 5, ≤5min timeout: +5 |
| Device Integrity | 15 | Not rooted/jailbroken |
| Hardware Attestation | 10 | Valid TPM/SE attestation |
| **Total** | **100** | |

## Compliance Thresholds

| Level | Score | Access |
|-------|-------|--------|
| Full | ≥80 | All resources |
| Standard | ≥70 | Standard resources |
| Limited | ≥50 | Read-only access |
| Denied | <50 | No access |

## Data Structure

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevicePosture {
    // Platform info
    pub platform: String,
    pub os_version: String,
    pub os_build: String,
    pub device_model: String,
    pub serial_number: Option<String>,
    
    // Security software
    pub antivirus_active: bool,
    pub antivirus_name: Option<String>,
    pub firewall_enabled: bool,
    pub edr_installed: bool,
    pub edr_name: Option<String>,
    
    // Encryption
    pub disk_encrypted: bool,
    pub encryption_type: Option<String>,
    
    // Patch status
    pub os_patch_age_days: u32,
    pub pending_security_updates: u32,
    
    // Security configuration
    pub screen_lock_enabled: bool,
    pub screen_lock_timeout: Option<u32>,
    pub password_complexity: PasswordComplexity,
    pub biometric_enabled: bool,
    
    // Risk indicators
    pub is_jailbroken: bool,
    pub is_rooted: bool,
    pub developer_mode_enabled: bool,
    
    // Network
    pub wifi_security: Option<WifiSecurity>,
    pub vpn_active: bool,
    
    // Hardware attestation
    pub hardware_attestation: Option<HardwareAttestation>,
    
    // Metadata
    pub collected_at: DateTime<Utc>,
    pub score: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareAttestation {
    pub platform: String,
    pub attestation_type: String,  // "tpm2", "secure_enclave", "key_attestation"
    pub attestation_data: String,  // Base64 encoded
    pub timestamp: DateTime<Utc>,
}
```

## Collection Frequency

| Trigger | Interval |
|---------|----------|
| Connection | Immediate |
| Periodic | 60 seconds |
| Network Change | Immediate |
| App Foreground | Immediate |
| Policy Refresh | On-demand |

## Privacy Considerations

1. **Local Processing**: All checks run locally
2. **Minimal Data**: Only security-relevant attributes transmitted
3. **No App Lists**: Individual app names not sent (only categories)
4. **No User Data**: No personal data collected
5. **Opt-out**: Users can disable specific checks (with access impact)
