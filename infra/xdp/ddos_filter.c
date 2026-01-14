/*
 * XDP DDoS Filter - First Line Defense
 *
 * Compiles with: clang -O2 -g -target bpf -c ddos_filter.c -o ddos_filter.o
 * Load with: ip link set dev eth0 xdp obj ddos_filter.o sec xdp_ddos
 */

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* === BPF Maps === */

/* IP Blocklist - Hash map of blocked IPs */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 100000);
  __type(key, __u32);   /* IPv4 address */
  __type(value, __u64); /* Block timestamp */
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist SEC(".maps");

/* IPv6 Blocklist */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 50000);
  __type(key, struct in6_addr);
  __type(value, __u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_v6 SEC(".maps");

/* Network Blocklist - LPM trie for CIDR blocks */
struct lpm_key {
  __u32 prefixlen;
  __u32 addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 10000);
  __type(key, struct lpm_key);
  __type(value, __u64);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_lpm SEC(".maps");

/* Per-IP Rate Limits */
struct rate_limit {
  __u64 pps_limit;
  __u64 bps_limit;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 100000);
  __type(key, __u32);
  __type(value, struct rate_limit);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} rate_limits SEC(".maps");

/* Rate limit state per IP */
struct rate_state {
  __u64 packets;
  __u64 bytes;
  __u64 last_reset;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 100000);
  __type(key, __u32);
  __type(value, struct rate_state);
} rate_state SEC(".maps");

/* Global Statistics (per-CPU) */
struct xdp_stats {
  __u64 packets_received;
  __u64 packets_dropped;
  __u64 packets_passed;
  __u64 bytes_received;
  __u64 bytes_dropped;
  __u64 blocklist_hits;
  __u64 rate_limit_hits;
  __u64 syn_verified;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct xdp_stats);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats SEC(".maps");

/* SYN Cookie Secrets */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u64);
} syn_secrets SEC(".maps");

/* === Helper Functions === */

static __always_inline __u32 get_syn_cookie(__u32 saddr, __u32 daddr,
                                            __u16 sport, __u16 dport) {
  __u32 key = 0;
  __u64 *secret = bpf_map_lookup_elem(&syn_secrets, &key);
  if (!secret)
    return 0;

  /* Simple hash - real implementation would use siphash */
  return (saddr ^ daddr ^ sport ^ dport ^ (*secret)) & 0xFFFFFFFF;
}

static __always_inline int check_blocklist(__u32 saddr) {
  /* Check exact IP match */
  if (bpf_map_lookup_elem(&blocklist, &saddr))
    return 1;

  /* Check LPM trie for network blocks */
  struct lpm_key key = {.prefixlen = 32, .addr = saddr};
  if (bpf_map_lookup_elem(&blocklist_lpm, &key))
    return 1;

  return 0;
}

static __always_inline int check_rate_limit(__u32 saddr, __u32 pkt_len) {
  struct rate_limit *limit = bpf_map_lookup_elem(&rate_limits, &saddr);
  if (!limit)
    return 0; /* No limit configured */

  struct rate_state *state = bpf_map_lookup_elem(&rate_state, &saddr);
  if (!state) {
    struct rate_state new_state = {
        .packets = 1, .bytes = pkt_len, .last_reset = bpf_ktime_get_ns()};
    bpf_map_update_elem(&rate_state, &saddr, &new_state, BPF_ANY);
    return 0;
  }

  __u64 now = bpf_ktime_get_ns();
  __u64 elapsed = now - state->last_reset;

  /* Reset every second */
  if (elapsed >= 1000000000ULL) {
    state->packets = 1;
    state->bytes = pkt_len;
    state->last_reset = now;
    return 0;
  }

  /* Check limits */
  if (limit->pps_limit > 0 && state->packets >= limit->pps_limit)
    return 1;

  if (limit->bps_limit > 0 && state->bytes >= limit->bps_limit)
    return 1;

  /* Update counters */
  state->packets++;
  state->bytes += pkt_len;

  return 0;
}

/* === Main XDP Program === */

SEC("xdp_ddos")
int xdp_ddos_filter(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  /* Statistics key */
  __u32 stats_key = 0;
  struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats, &stats_key);
  if (!stats)
    return XDP_PASS;

  __u32 pkt_len = data_end - data;
  stats->packets_received++;
  stats->bytes_received += pkt_len;

  /* Parse Ethernet header */
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  __u16 eth_proto = bpf_ntohs(eth->h_proto);

  /* Handle IPv4 */
  if (eth_proto == ETH_P_IP) {
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
      return XDP_PASS;

    __u32 saddr = ip->saddr;

    /* Check blocklist */
    if (check_blocklist(saddr)) {
      stats->packets_dropped++;
      stats->bytes_dropped += pkt_len;
      stats->blocklist_hits++;
      return XDP_DROP;
    }

    /* Check rate limit */
    if (check_rate_limit(saddr, pkt_len)) {
      stats->packets_dropped++;
      stats->bytes_dropped += pkt_len;
      stats->rate_limit_hits++;
      return XDP_DROP;
    }

    /* TCP-specific checks */
    if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
      if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

      /* SYN packet - verify or cookie */
      if (tcp->syn && !tcp->ack) {
        /* For high-rate SYN floods, could implement SYN cookies here */
        /* Currently just pass - VPP handles SYN cookies */
      }
    }

    /* UDP amplification protection */
    if (ip->protocol == IPPROTO_UDP) {
      struct udphdr *udp = (void *)ip + (ip->ihl * 4);
      if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

      __u16 sport = bpf_ntohs(udp->source);

      /* Block common amplification ports */
      if (sport == 19 ||    /* Chargen */
          sport == 53 ||    /* DNS - check size */
          sport == 123 ||   /* NTP */
          sport == 161 ||   /* SNMP */
          sport == 389 ||   /* LDAP */
          sport == 1900 ||  /* SSDP */
          sport == 11211) { /* Memcached */

        /* Large UDP from these ports = amplification */
        if (pkt_len > 512) {
          stats->packets_dropped++;
          stats->bytes_dropped += pkt_len;
          return XDP_DROP;
        }
      }
    }
  }

  /* Handle IPv6 */
  else if (eth_proto == ETH_P_IPV6) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
      return XDP_PASS;

    /* Check IPv6 blocklist */
    if (bpf_map_lookup_elem(&blocklist_v6, &ip6->saddr)) {
      stats->packets_dropped++;
      stats->bytes_dropped += pkt_len;
      stats->blocklist_hits++;
      return XDP_DROP;
    }
  }

  stats->packets_passed++;
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
