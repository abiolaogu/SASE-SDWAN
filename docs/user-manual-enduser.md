# End User Manual -- SASE-SDWAN Platform
> Version: 1.0 | Last Updated: 2026-02-17 | Status: Draft
> Classification: Internal | Author: AIDD System

## 1. Overview

As an end user, you connect to your organization's network and applications through the OpenSASE platform. The platform provides secure access to corporate resources from any location using Zero Trust Network Access (ZTNA) and SD-WAN connectivity.

## 2. Desktop Client Installation

### 2.1 Windows
1. Download `OpenSASE-Setup.exe` from your organization's portal
2. Run the installer and follow the prompts
3. The client appears in the system tray after installation
4. Uses `opensase-clients/windows/OpenSaseClient.cs` native integration

### 2.2 macOS
1. Download `OpenSASE.dmg` from your organization's portal
2. Drag the app to Applications folder
3. On first launch, approve the VPN configuration prompt
4. Uses `opensase-clients/macos/OpenSASEApp.swift` native integration

### 2.3 Linux
1. Download the `.deb` or `.rpm` package
2. Install: `sudo dpkg -i opensase-client.deb` or `sudo rpm -i opensase-client.rpm`
3. Launch from application menu or command line: `opensase-client`
4. Built from `client/core/` Rust library with `client/linux/` platform layer

## 3. Mobile App Installation

### 3.1 iOS
1. Download "OpenSASE" from the App Store
2. Open and sign in with your corporate credentials
3. Approve VPN configuration when prompted
4. Uses `opensase-clients/ios/OpenSASEApp.swift`

### 3.2 Android
1. Download "OpenSASE" from Google Play Store
2. Open and sign in with your corporate credentials
3. Approve VPN configuration when prompted
4. Uses `opensase-clients/android/OpenSaseClient.kt`

## 4. Connecting to the Network

### 4.1 First-Time Setup
1. Open the OpenSASE client
2. Enter your organization's server URL (provided by IT)
3. Click "Sign In" -- this opens a browser window for Keycloak OIDC authentication
4. Enter your corporate username and password
5. Complete MFA if enabled (recommended)
6. The client will:
   - Verify your device posture (OS version, antivirus, disk encryption)
   - Download your access policy
   - Establish a secure WireGuard tunnel

### 4.2 Connecting

Once signed in:
1. Click the "Connect" button in the client
2. The status indicator turns green when connected
3. All traffic to corporate resources is now encrypted and routed through the secure tunnel
4. You can access private applications without additional VPN setup

### 4.3 Disconnecting
1. Click the "Disconnect" button
2. The tunnel is closed gracefully
3. You retain local internet access

## 5. Accessing Applications

### 5.1 Private Applications (ZTNA)
Your IT team has configured certain applications as "dark services" -- they have no public IP address and are only accessible through OpenSASE ZTNA.

To access:
1. Ensure the client is connected
2. Open your browser and navigate to the application URL (e.g., `http://app1.internal`)
3. The Ziti fabric routes your request to the application
4. No additional authentication needed (your session is already verified)

### 5.2 Web Applications
Regular web browsing is protected by the Secure Web Gateway:
- Malicious websites are automatically blocked
- DNS queries are filtered for known threats
- IPS inspects traffic for attack signatures

### 5.3 Application Status
The client shows available applications and their status:
- **Available**: Application reachable through the tunnel
- **Degraded**: Application reachable but with high latency
- **Unavailable**: Application not reachable (contact IT)

## 6. Understanding Security Features

### 6.1 Device Posture Checks
The client periodically checks your device's security posture (from `client/core/src/posture.rs`):
- Operating system version (must be up to date)
- Antivirus software (must be active)
- Disk encryption (must be enabled)
- Firewall (must be active)

If your device fails a posture check, access may be restricted. The client will show which check failed and how to fix it.

### 6.2 Data Loss Prevention
The DLP engine monitors uploads to cloud services. If you attempt to upload a file containing sensitive data (SSN, credit card numbers, API keys), the upload may be blocked. You will see a notification explaining why.

### 6.3 Remote Browser Isolation
For high-risk websites, your browser may use Remote Browser Isolation (RBI). The website is rendered in a remote container, and only the visual output is sent to your browser. This protects your device from web-based attacks.

## 7. Troubleshooting

### 7.1 Cannot Connect

| Symptom | Possible Cause | Solution |
|---------|---------------|----------|
| "Authentication failed" | Wrong credentials | Reset password via Keycloak |
| "Posture check failed" | Device not compliant | Update OS, enable antivirus/encryption |
| "Server unreachable" | Network issue | Check internet connectivity |
| "Tunnel failed" | Firewall blocking | Allow UDP 51820 (WireGuard) outbound |

### 7.2 Slow Performance
1. Check the tunnel latency in the client status panel
2. If latency > 200ms, contact IT to check path selection
3. Try disconnecting and reconnecting to force a new path
4. If on Wi-Fi, try a wired connection

### 7.3 Application Not Loading
1. Verify the client is connected (green indicator)
2. Check the application is listed in your available apps
3. Try refreshing the browser
4. Clear browser cache and try again
5. Contact IT if the issue persists

### 7.4 Client Crashes
1. Check for client updates
2. Restart the client application
3. If persistent, collect logs: Settings > Export Logs
4. Send logs to IT support

## 8. Privacy Information

### 8.1 What Is Monitored
- Network flow metadata (source/destination IPs, ports, protocols)
- DNS queries (for security filtering)
- Application usage categories
- Device posture status

### 8.2 What Is NOT Monitored
- Email content
- File contents (unless DLP policy triggers)
- Keystroke logging
- Screen recording
- Personal application usage on personal devices

### 8.3 Data Retention
- Session logs: retained for 24 hours
- Flow records: retained for 7 days
- Security alerts: retained for 1 year
- Audit logs: retained per compliance requirements

## 9. Getting Help

| Channel | Hours | Use For |
|---------|-------|---------|
| Self-service portal | 24/7 | Password reset, status check |
| IT Help Desk | Business hours | Configuration issues, access requests |
| Emergency line | 24/7 | Security incidents, complete outages |

## 10. Keyboard Shortcuts (Desktop Client)

| Shortcut | Action |
|----------|--------|
| Ctrl/Cmd + Shift + C | Toggle connection |
| Ctrl/Cmd + Shift + S | Open status panel |
| Ctrl/Cmd + Shift + L | Export logs |
| Ctrl/Cmd + Q | Quit client |
