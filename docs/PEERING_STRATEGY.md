# OpenSASE Peering Strategy

## Overview

OpenSASE achieves Cloudflare-like network proximity through strategic IXP peering.
This reduces latency by 20-50% by being "one hop away" from end users.

## Latency Impact

```
Traditional (Via Transit):
User → ISP → Transit Provider → PoP
Latency: 30-80ms | Hops: 4-8

With IXP Peering:
User → ISP → IXP → PoP
Latency: 5-20ms | Hops: 2-3
```

---

## Peering Policy

**Policy: Open**

We peer openly with networks that meet these criteria:
- Valid ASN with acceptable traffic ratio
- Presence at common IXP
- Responsive NOC (24x7 contact)
- Will accept prefixes only from our AS-SET

**Contact**: peering@opensase.io

---

## Priority Targets

### Tier 1: CDN/Content (Highest Priority)
| ASN | Network | Reason |
|-----|---------|--------|
| 13335 | Cloudflare | Major CDN |
| 15169 | Google | Search, YouTube, Cloud |
| 32934 | Facebook/Meta | Social, WhatsApp |
| 16509 | Amazon AWS | Cloud infrastructure |
| 8075 | Microsoft | Azure, O365, Teams |
| 20940 | Akamai | CDN |
| 2906 | Netflix | Streaming |

### Tier 2: Major ISPs
| ASN | Network | Region |
|-----|---------|--------|
| 3320 | Deutsche Telekom | Europe |
| 7922 | Comcast | US |
| 7018 | AT&T | US |
| 701 | Verizon | US |
| 6830 | Liberty Global | Europe |

### Tier 3: Transit/Tier-1
| ASN | Network | Notes |
|-----|---------|-------|
| 174 | Cogent | Tier-1 |
| 3356 | Lumen/Level3 | Tier-1 |
| 1299 | Telia | Tier-1 |
| 6939 | Hurricane Electric | Large IX presence |

---

## IXP Presence

### Phase 1: Europe (Month 1-2)
| IXP | City | Port | Status |
|-----|------|------|--------|
| DE-CIX | Frankfurt | 10G | ⏳ |
| AMS-IX | Amsterdam | 10G | ⏳ |
| LINX | London | 10G | ⏳ |

### Phase 2: North America (Month 2-3)
| IXP | City | Port | Status |
|-----|------|------|--------|
| Equinix | Ashburn | 10G | ⏳ |
| Equinix | New York | 10G | ⏳ |
| SIX | Seattle | 10G | ⏳ |

### Phase 3: Asia Pacific (Month 3-4)
| IXP | City | Port | Status |
|-----|------|------|--------|
| HKIX | Hong Kong | 10G | ⏳ |
| JPIX | Tokyo | 10G | ⏳ |
| SGIX | Singapore | 10G | ⏳ |

---

## Route Policy

### Communities
| Community | Meaning |
|-----------|---------|
| 65100:100 | Learned from IXP |
| 65100:200 | Learned from Transit |
| 65100:300 | Customer route |
| 65100:666 | Blackhole |

### Local Preference
| Source | Local Pref | Priority |
|--------|------------|----------|
| Customer | 200 | Highest |
| IXP Direct (1-hop) | 200 | High |
| IXP 2-hop | 150 | Medium |
| Transit | 50 | Backup |

### Export Policy
- IXP: Our prefixes + customer routes
- Transit: Our prefixes + customer routes (with AS prepend)

---

## RPKI Strategy

1. **Create ROAs** for all prefixes at RIR
2. **Validate inbound** routes via RPKI
3. **Reject invalid** routes in BIRD
4. **Boost valid** routes with +10 local pref

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Established sessions | >50 |
| Prefixes received | >200K |
| Traffic via IXP | >80% |
| Latency reduction | >30% |
| Transit dependency | <20% |
