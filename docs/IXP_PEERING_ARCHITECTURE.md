# OpenSASE IXP Peering Architecture

## Latency Reduction Through Direct Peering

### Traditional Path (Via Transit)
```
User → ISP → Transit Provider → Your PoP
Latency: 30-80ms | Hops: 4-8
```

### With IXP Peering
```
User → ISP → IXP → Your PoP
Latency: 5-20ms | Hops: 2-3
```

**Target: 20-50% latency reduction**

---

## Target IXPs (Priority Order)

### Tier 1 - Must Have (Deploy First)

| Region | IXP | Members | Peak Traffic | Port Cost (10G) |
|--------|-----|---------|--------------|-----------------|
| Europe | DE-CIX Frankfurt | 1000+ | 15 Tbps | €1,500/mo |
| Europe | AMS-IX Amsterdam | 900+ | 12 Tbps | €1,200/mo |
| Europe | LINX London | 900+ | 8 Tbps | £1,000/mo |
| NA | Equinix IX NYC | 500+ | 5 Tbps | $2,000/mo |
| NA | Equinix IX Ashburn | 400+ | 4 Tbps | $2,000/mo |

### Tier 2 - High Value

| Region | IXP | Members | Peak Traffic | Port Cost (10G) |
|--------|-----|---------|--------------|-----------------|
| Asia | HKIX Hong Kong | 300+ | 3 Tbps | HKD 10,000/mo |
| Asia | JPIX Tokyo | 200+ | 2 Tbps | ¥150,000/mo |
| Asia | SGIX Singapore | 200+ | 1.5 Tbps | SGD 2,000/mo |
| NA | SIX Seattle | 300+ | 2 Tbps | $1,500/mo |
| NA | Any2 Los Angeles | 200+ | 1.5 Tbps | $1,200/mo |

### Tier 3 - Regional Coverage

| Region | IXP | Members | Notes |
|--------|-----|---------|-------|
| Europe | France-IX Paris | 400+ | French market |
| Europe | NL-ix | 200+ | Dutch enterprises |
| Europe | SwissIX | 150+ | Swiss finance |
| LATAM | IX.br São Paulo | 1500+ | Latin America hub |
| APAC | KINX Seoul | 150+ | Korean market |

---

## Deployment Strategy

### Phase 1: European Hub (Month 1-2)
```
┌─────────────────────────────────────────────┐
│           DE-CIX Frankfurt (Hub)            │
│                    ↓                        │
│     ┌──────────────┼──────────────┐         │
│     ↓              ↓              ↓         │
│  AMS-IX        LINX LON1      France-IX     │
└─────────────────────────────────────────────┘
```

**Target Peers at DE-CIX:**
- Cloudflare (AS13335) - CDN
- Google (AS15169) - Content
- Facebook (AS32934) - Social
- Deutsche Telekom (AS3320) - Regional ISP
- Hurricane Electric (AS6939) - Transit

### Phase 2: North American Expansion (Month 2-3)
```
┌─────────────────────────────────────────────┐
│        Equinix Ashburn (Hub)                │
│                    ↓                        │
│     ┌──────────────┼──────────────┐         │
│     ↓              ↓              ↓         │
│  Equinix NYC  SIX Seattle    Any2 LA        │
└─────────────────────────────────────────────┘
```

**Target Peers at Equinix Ashburn:**
- Amazon (AS16509)
- Microsoft (AS8075)
- Comcast (AS7922)
- AT&T (AS7018)
- Verizon (AS701)

### Phase 3: Asia-Pacific (Month 3-4)
```
┌─────────────────────────────────────────────┐
│           SGIX Singapore (Hub)              │
│                    ↓                        │
│     ┌──────────────┼──────────────┐         │
│     ↓              ↓              ↓         │
│   HKIX         JPIX Tokyo      KINX Seoul   │
└─────────────────────────────────────────────┘
```

---

## BGP Configuration

### Route Server Peering
```
# Automatic peering with 100+ networks via RS
neighbor 80.81.192.157 as 6695  # DE-CIX RS1
neighbor 80.81.192.158 as 6695  # DE-CIX RS2
```

### Bilateral Peering (Priority Networks)
```
# Direct sessions with major CDNs
neighbor 80.81.193.13 as 13335  # Cloudflare
neighbor 80.81.193.15 as 15169  # Google
neighbor 80.81.193.32 as 32934  # Facebook
```

### Communities
| Community | Meaning |
|-----------|---------|
| 65100:100 | Learned from IXP |
| 65100:200 | Learned from Transit |
| 65100:300 | Customer Route |
| 65100:10 | Region: North America |
| 65100:20 | Region: Europe |
| 65100:30 | Region: Asia Pacific |

---

## Expected Results

### Latency Improvements

| User Location | Before (Transit) | After (IXP) | Improvement |
|---------------|------------------|-------------|-------------|
| Frankfurt | 45ms | 8ms | -82% |
| Amsterdam | 52ms | 12ms | -77% |
| London | 48ms | 10ms | -79% |
| New York | 35ms | 5ms | -86% |
| Singapore | 65ms | 15ms | -77% |

### Traffic Shift

| Path | Before | After |
|------|--------|-------|
| Transit | 100% | 20% |
| IXP (Route Server) | 0% | 40% |
| IXP (Bilateral) | 0% | 40% |

### Cost Impact

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Transit Cost | $50/Mbps | $10/Mbps | -80% |
| Total Monthly (10 Gbps) | $500,000 | $150,000 | -70% |

---

## Port Specifications

### Standard Configuration
- **Speed**: 10 Gbps (upgradeable to 100G)
- **Media**: Single-mode fiber (LR)
- **MTU**: 9000 (jumbo frames)
- **VLAN**: Tagged (802.1Q)

### Required Equipment at Each IXP
1. Cross-connect to IXP patch panel
2. DPDK-compatible NIC (Intel/Mellanox)
3. VPP with BGP (BIRD) integration
4. RPKi validator for route security

---

## Peering Policy

### OpenSASE Peering Requirements
- **ASN**: AS65100 (placeholder)
- **Policy**: Open
- **PeeringDB**: Listed
- **Contact**: peering@opensase.io

### We Will Peer With
- Open and selective policy networks
- Networks with traffic ratio < 5:1
- Networks present at same IXP

### Technical Requirements
- Valid IRR entry (RADB/RIPE)
- Max prefix limit enforced
- MD5 authentication (optional)
- IPv4 and IPv6 support

---

## Monitoring

### Metrics to Track
- Prefixes received per peer
- Traffic per session (in/out)
- Latency per peer (RTT)
- Session uptime
- Route changes

### Alerting
- Session down > 5 minutes
- Prefix count drops > 50%
- Latency increase > 100%
- Traffic asymmetry > 10:1
