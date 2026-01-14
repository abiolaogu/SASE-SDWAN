// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
// OpenSASE eBPF Maps

#ifndef __SASE_MAPS_H__
#define __SASE_MAPS_H__

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

// 5-tuple flow key
struct flow_key {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
  __u8 pad[3];
} __attribute__((packed));

// Policy decision
struct policy_decision {
  __u8 action;
  __u8 inspection;
  __u16 rule_id;
  __u32 rate_limit;
  __u64 packets;
  __u64 bytes;
} __attribute__((packed));

// Policy entry
struct policy {
  __u8 action;
  __u8 inspection;
  __u16 rule_id;
  __u32 rate_limit;
};

// LPM trie key for CIDR matching
struct lpm_key {
  __u32 prefixlen;
  __u32 addr;
};

// Flow cache: 5-tuple -> decision
// LRU hash for automatic eviction
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1000000); // 1M flows
  __type(key, struct flow_key);
  __type(value, struct policy_decision);
} flow_cache SEC(".maps");

// Policy trie: CIDR -> policy
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 100000);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key);
  __type(value, struct policy);
} policy_trie SEC(".maps");

// Per-CPU packet counter
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} packet_count SEC(".maps");

// Per-CPU byte counter
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} byte_count SEC(".maps");

// Segment VRF mapping
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u8);   // segment ID
  __type(value, __u8); // VRF ID
} segment_vrf SEC(".maps");

// Rate limiter (token bucket per flow)
struct rate_limit_entry {
  __u64 tokens;
  __u64 last_update;
  __u32 rate_pps;
  __u32 burst;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 100000);
  __type(key, struct flow_key);
  __type(value, struct rate_limit_entry);
} rate_limiters SEC(".maps");

// XDP redirect map (for multi-queue NIC)
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, __u32);
} xsk_map SEC(".maps");

// Perf event map for userspace notifications
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

#endif // __SASE_MAPS_H__
