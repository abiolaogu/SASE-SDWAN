# BGP Operations Guide

## Daily Operations

### Check Session Status
```bash
# List all BGP sessions
birdc show protocols

# Check specific session
birdc show protocols cloudflare_decix

# Show session details
birdc show protocols all cloudflare_decix
```

### Check Routes
```bash
# Show routes from a peer
birdc show route protocol cloudflare_decix

# Show route for specific prefix
birdc show route for 8.8.8.0/24 all

# Show best route
birdc show route for 8.8.8.0/24 primary

# Count routes from peer
birdc show route protocol rs1_decix count
```

### Check Filtering
```bash
# Show import filter result (dry run)
birdc show route protocol rs1_decix filtered

# Show export table
birdc show route export cloudflare_decix
```

---

## Session Management

### Enable/Disable Session
```bash
# Disable session
birdc disable cloudflare_decix

# Enable session
birdc enable cloudflare_decix

# Restart session (reset)
birdc restart cloudflare_decix
```

### Reload Configuration
```bash
# Check config syntax
birdc configure check

# Reload config (graceful)
birdc configure

# Force reload (drops sessions)
birdc configure soft
```

---

## Troubleshooting

### Session Not Establishing

1. **Check neighbor IP**
```bash
ping -c 3 80.81.193.13
```

2. **Check ASN configuration**
```bash
birdc show protocols all cloudflare_decix | grep neighbor
```

3. **Check for filters dropping everything**
```bash
birdc show route protocol cloudflare_decix rejected
```

4. **Check logs**
```bash
tail -100 /var/log/bird/bird.log | grep cloudflare
```

### Session Flapping

1. **Check error reason**
```bash
birdc show protocols all cloudflare_decix | grep -i error
```

2. **Common issues**:
   - Hold timer expired: Increase hold/keepalive
   - Prefix limit exceeded: Increase import limit
   - MD5 mismatch: Check password

3. **Enable BFD monitoring**
```bash
birdc show bfd sessions
```

### RPKI Issues

1. **Check RPKI connection**
```bash
birdc show protocols rpki_cloudflare
```

2. **Check ROA table**
```bash
birdc show roa
birdc show route where roa_check(roa_v4, net, bgp_path.last) = ROA_INVALID
```

---

## Adding New Peer

### 1. Get peer info from PeeringDB
```bash
curl "https://api.peeringdb.com/api/net?asn=13335" | jq
```

### 2. Add to BIRD config
```bird
protocol bgp new_peer from tpl_bilateral {
    description "New Peer via DE-CIX";
    neighbor 80.81.193.X as NEW_ASN;
}
```

### 3. Reload config
```bash
birdc configure
birdc show protocols new_peer
```

### 4. Verify routes
```bash
birdc show route protocol new_peer count
```

---

## Emergency Procedures

### Blackhole Attack Traffic
```bash
# Add blackhole route
birdc add route 192.0.2.0/24 blackhole

# Remove blackhole
birdc delete route 192.0.2.0/24 blackhole
```

### Disable All Peering (Emergency)
```bash
# Disable all BGP
for proto in $(birdc show protocols | grep BGP | awk '{print $1}'); do
    birdc disable $proto
done

# Re-enable
for proto in $(birdc show protocols | grep BGP | awk '{print $1}'); do
    birdc enable $proto
done
```

### Route Leak Detection
```bash
# Check for unexpected prefixes
birdc show route where bgp_path.len < 3 and net.len < 16
```

---

## Monitoring Commands

### Session Health
```bash
# All sessions summary
birdc show protocols | grep -E "BGP|Established|down"

# Sessions with problems
birdc show protocols | grep -v Established | grep BGP

# Uptime check
birdc show protocols all | grep -E "State|Uptime"
```

### Traffic Metrics
```bash
# Interface stats
vppctl show interface

# Per-peer traffic (via VPP ACL counters)
vppctl show acl-plugin acl
```

### Export Prometheus metrics
```bash
curl http://localhost:9100/metrics | grep ospe_
```

---

## Scheduled Maintenance

### Before Maintenance
```bash
# Graceful shutdown (announce to peers)
birdc graceful shutdown

# Or set lower local pref
birdc eval 'bgp_local_pref = 10'
```

### After Maintenance
```bash
# Resume normal operation
birdc graceful restart cancel
birdc configure
```
