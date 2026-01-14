# FlexiWAN Manual Enrollment Guide

This guide documents all manual steps required due to FlexiWAN's limited OSS API.

## Overview

FlexiWAN's open-source version has a limited REST API compared to the commercial version. This guide provides step-by-step manual procedures for operations that cannot be fully automated.

---

## 1. Initial Controller Setup

### First-Time Login

1. Open FlexiWAN UI: **http://localhost:3000**
2. Create admin account (first-time only):
   - Email: `admin@opensase.lab`
   - Password: (your choice, update in `.env`)
3. Verify email (development mode auto-confirms)

### Create Organization

1. Navigate to: **Settings** → **Organizations**
2. Click **Add Organization**
3. Fill in:
   - Name: `OpenSASE Lab`
   - Description: `SASE Security Lab`
4. Click **Save**

---

## 2. Network Segmentation (VRF) Setup

### Create Segments

FlexiWAN segments provide VRF-like logical separation.

1. Navigate to: **Settings** → **Segments**
2. Click **Add Segment**

**Corp Segment:**
| Field | Value |
|-------|-------|
| Name | corp |
| Segment ID | 1 |
| Description | Corporate traffic - routes via PoP |
| Color | Blue (#4285f4) |

**Guest Segment:**
| Field | Value |
|-------|-------|
| Name | guest |
| Segment ID | 2 |
| Description | Guest traffic - local breakout |
| Color | Yellow (#fbbc04) |

---

## 3. Device Token Generation

### Generate Tokens for Each Edge

1. Navigate to: **Inventory** → **Device Tokens**
2. For each branch (branch-a, branch-b, branch-c):
   - Click **Create Token**
   - Device Name: `branch-a` (etc.)
   - Click **Generate**
   - **Copy the token immediately** (shown only once)

3. Save tokens to `.env`:
   ```bash
   BRANCH_A_TOKEN=eyJhbG...
   BRANCH_B_TOKEN=eyJhbG...
   BRANCH_C_TOKEN=eyJhbG...
   ```

4. Or save to `.device-tokens` file:
   ```
   branch-a=eyJhbG...
   branch-b=eyJhbG...
   branch-c=eyJhbG...
   ```

---

## 4. Edge Device Enrollment

### Start Edge Containers

```bash
# After setting tokens
docker compose up -d branch-a branch-b branch-c
```

### Approve Devices in UI

1. Navigate to: **Inventory** → **Devices**
2. New devices appear with status "Pending"
3. For each device:
   - Click the device name
   - Review the device info
   - Click **Approve**

### Configure Device Interfaces

After approval, configure each device:

1. Click device name → **Interfaces** tab
2. Set interface roles:
   
   | Interface | Type | IP Assignment |
   |-----------|------|---------------|
   | eth0 | WAN | DHCP or Static |
   | eth1 | WAN | Static (backup) |
   | eth2 | LAN | Static |

3. Enable interfaces and click **Apply**

### Assign to Segments

1. Device → **Segments** tab
2. Assign LAN interface to segments:
   - VLAN 100 → corp segment
   - VLAN 200 → guest segment
3. Click **Apply**

---

## 5. Tunnel Configuration

### Create Tunnels Between Sites

1. Navigate to: **Tunnels**
2. Click **Create Tunnel**

**branch-a to PoP:**
| Field | Value |
|-------|-------|
| Site A | branch-a |
| Site B | pop-gateway |
| Encryption | WireGuard |
| Path Labels | Primary: WAN1, Backup: WAN2 |

Repeat for branch-b and branch-c.

### Verify Tunnel Status

1. Navigate to: **Tunnels**
2. All tunnels should show **Connected** status
3. Check latency and packet loss metrics

---

## 6. Routing Policies

### Create Corp Policy (via PoP)

1. Navigate to: **Policies** → **Routing**
2. Click **Add Policy**

| Field | Value |
|-------|-------|
| Name | corp-via-pop |
| Priority | 100 |
| Match Segment | corp |
| Action | Route to Hub |
| Path Selection | Primary WAN1, Fallback WAN2 |

### Create Guest Policy (Local Breakout)

| Field | Value |
|-------|-------|
| Name | guest-local-breakout |
| Priority | 100 |
| Match Segment | guest |
| Action | Local Internet Breakout |
| Preferred WAN | WAN1 |

### Apply Policies to Devices

1. Navigate to: **Devices** → Select device
2. Go to **Policies** tab
3. Enable desired policies
4. Click **Apply**

---

## 7. Link Failover Configuration

### Configure Path Metrics

1. Device → **Path Selection** tab
2. Set path monitoring:
   
   | Setting | Value |
   |---------|-------|
   | Probe Interval | 5 seconds |
   | Latency Threshold | 100ms |
   | Packet Loss Threshold | 5% |
   | Jitter Threshold | 30ms |

3. Set failover behavior:
   - Primary Path: WAN1 (eth0)
   - Backup Path: WAN2 (eth1)
   - Failback: Automatic after 30s stable

---

## 8. Verification Steps

### Check Device Status

```bash
# Via API (if available)
curl http://localhost:3000/api/devices \
  -H "Authorization: Bearer $TOKEN"

# Via Docker
docker exec branch-a wg show
```

### Check Tunnel Status

```bash
# Via API
curl http://localhost:3000/api/tunnels \
  -H "Authorization: Bearer $TOKEN"
```

### Test Connectivity

```bash
# From branch-a to PoP
docker exec branch-a ping -c 3 10.200.0.1

# Branch-to-branch via overlay
docker exec branch-a ping -c 3 10.202.0.1
```

---

## 9. API Endpoints Reference

Available OSS API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Get auth token |
| `/api/devices` | GET | List devices |
| `/api/devices/{id}` | GET | Device details |
| `/api/tunnels` | GET | List tunnels |
| `/api/organizations` | GET | List orgs |

### Example API Calls

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@opensase.lab","password":"YOUR_PASSWORD"}' \
  | jq -r '.token')

# List devices
curl -s http://localhost:3000/api/devices \
  -H "Authorization: Bearer $TOKEN" | jq

# Get specific device
curl -s http://localhost:3000/api/devices/DEVICE_ID \
  -H "Authorization: Bearer $TOKEN" | jq
```

---

## 10. Troubleshooting

### Device Not Appearing

1. Check token is correct in environment
2. Verify controller URL is reachable from edge
3. Check edge logs: `docker logs branch-a`

### Tunnel Not Connecting

1. Verify both devices are approved and interfaces configured
2. Check WireGuard is running: `docker exec branch-a wg show`
3. Verify firewall allows UDP 51820

### Policy Not Applying

1. Ensure policy is enabled on device
2. Check segment assignment matches policy
3. Verify traffic is correctly tagged to segment

---

## Automation Limitations

| Feature | API Available | Automation Level |
|---------|---------------|------------------|
| Device tokens | Partial | Script generates request |
| Device approval | No | Manual UI required |
| Interface config | Limited | Manual UI required |
| Tunnel creation | Limited | Manual UI required |
| Policies | Partial | Template-based |
| Monitoring | Yes | Fully automated |

---

## Integration with Scripts

The bootstrap scripts prepare everything possible:

```bash
# 1. Bootstrap controller (creates org, segments, policies definitions)
./scripts/flexiwan-bootstrap.sh

# 2. Generate edge configs
./scripts/flexiwan-edge-bootstrap.sh

# 3. Manual steps in UI (this guide)

# 4. Once enrolled, test
./scripts/test-sdwan.sh
```

---

## Quick Reference Card

### URLs
- Controller UI: http://localhost:3000
- API Base: http://localhost:3000/api

### Default Credentials
- Email: admin@opensase.lab
- Password: (see .env FLEXIWAN_ADMIN_PASSWORD)

### Network Ranges
- PoP: 10.200.0.0/24
- Branch A: 10.201.0.0/24
- Branch B: 10.202.0.0/24
- Branch C: 10.203.0.0/24
- Overlay: 10.210.0.0/24

### Segment IDs
- Corp: 1 (VLAN 100)
- Guest: 2 (VLAN 200)
